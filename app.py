import logging
import sys
import config
import requests
import praw

from flask import Flask, request, session, redirect, url_for, render_template, abort
from pymongo import MongoClient
from requests_oauthlib import OAuth2Session
from itsdangerous import JSONWebSignatureSerializer
from datetime import datetime as dt, timedelta
from werkzeug import exceptions

app = Flask(__name__)

mongo = MongoClient(host=config.DB_HOST, port=int(config.DB_PORT), username=config.DB_USERNAME,
                    password=config.DB_PASSWORD, authSource=config.DB_DATABASE, authMechanism='SCRAM-SHA-1')

db = mongo[config.DB_DATABASE]

checkBanR = praw.Reddit(client_id=config.PRAW_CLIENT_ID,
                        client_secret=config.PRAW_CLIENT_SECRET, password=config.PRAW_PASSWORD,
                        user_agent=config.PRAW_USER_AGENT, username=config.PRAW_USERNAME)

# noinspection PyArgumentList
logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s]\t %(name)s: %(message)s", handlers=[
    logging.StreamHandler(sys.stdout),
    logging.FileHandler(config.LOGGING_FILENAME)
])

logging.getLogger('werkzeug').setLevel(logging.ERROR)


@app.route("/")
def verify():
    if "discord" in session and "reddit" in session:
        pass
    elif "reddit" in session:
        # Populate the session with Discord data, if it exists.
        discord_user = db.users.find_one({"reddit.id": session["reddit"]["id"]}) or []
        if "discord" in discord_user:
            session["discord"] = {k: v for (k, v) in discord_user["discord"].items() if k in ["id", "name"]}
    elif "discord" in session:
        if "reddit" not in db.users.find_one({"discord.id": session["discord"]["id"]}):
            db.users.find_one_and_delete({"discord.id": session["discord"]["id"]})

        return redirect(url_for("logout"))

    return render_template("verify.html", session=session)


@app.route('/login/discord')
def login_discord():
    user = confirm_login(config.DISCORD_REDIRECT_BASE_URL + "/login/discord")
    if isinstance(user, dict):
        # Save that to the db if there is a reddit instance
        if "reddit" in session:
            reddit_user = db.users.find_one({"discord.id": user["id"]})
            discord_user = db.users.find_one({"reddit.id": session["reddit"]["id"]})

            # Check if the reddit instance or discord instance already exist in the database.
            # If one already exists but doesnt match the other, return an error
            if (reddit_user and 'reddit' in reddit_user and reddit_user["reddit"]["id"] != session["reddit"]["id"]) \
                    or (discord_user and 'discord' in discord_user and discord_user["discord"]["id"] != user["id"]):
                return "Error, that account is already affiliated <a href='/'>Return to Verify</a>"

            # If we update the whole discord obj, it gets rid of the auth
            _id = db.users.find_one_and_update(
                {"reddit.id": session["reddit"]["id"]},
                {"$set": {
                    "discord.id": user["id"],
                    "discord.username": user["username"],
                    "discord.discriminator": user["discriminator"],
                    "discord.name": user["name"],
                    "verified": True,
                    "verified_at": dt.utcnow().timestamp()
                }}
            )

            # Save that to the session for easy template access
            session["discord"] = {k: v for (k, v) in user.items() if k in ["id", "name"]}

            # Add the ID of that to the queue
            db.queue.insert_one({'ref': _id["_id"]})

        return redirect(url_for('verify'))

    if user:
        return user

    else:
        scope = ['identify']
        discord = make_discord_session(scope=scope, redirect_uri=config.DISCORD_REDIRECT_BASE_URL + "/login/discord")
        authorization_url, state = discord.authorization_url(
            config.DISCORD_AUTHORIZATION_URL,
            access_type="offline"
        )
        session['oauth2_state'] = state
        return redirect(authorization_url)


@app.route('/login/reddit')
def login_reddit():
    # Check for state and for 0 errors
    state = session.get('oauth2_state')
    if request.values.get('error'):
        error = {
            'message': 'There was an error authenticating with reddit: {}'.format(request.values.get('error')),
            'link': {
                "text": 'Return home',
                "href": url_for("verify")
            }
        }
        return render_template('error.html', session=session, error=error)

    if state and request.args.get('code'):
        # Fetch token
        client_auth = requests.auth.HTTPBasicAuth(config.REDDIT_CLIENT_ID, config.REDDIT_CLIENT_SECRET)
        post_data = {"grant_type": "authorization_code", "code": request.args.get('code'),
                     "redirect_uri": config.REDDIT_REDIRECT_URL}
        reddit_token = requests.post(config.REDDIT_API_BASE_URL + "/access_token", auth=client_auth, data=post_data,
                                     headers={'User-agent': 'Discord auth, /u/hwsukmods'}).json()

        if not reddit_token or 'access_token' not in reddit_token:
            return redirect(url_for('logout'))

        # Fetch the user
        user = get_reddit_user(reddit_token["access_token"])

        if ('status' in user):
            if (user['status'] == 'error'):
                return render_template('error.html', session=session, error=user)

        # Store api_key and token
        db.users.update_one(
            {"reddit.id": user['id']},
            {"$set": {"reddit.token": reddit_token}}
        )

        session.permanent = True
        return redirect(url_for('verify'))

    else:
        scope = ['identity']
        reddit = make_reddit_session(scope=scope)
        authorization_url, state = reddit.authorization_url(
            config.REDDIT_API_BASE_URL + "/authorize",
            access_type="offline"
        )
        session['oauth2_state'] = state
        return redirect(authorization_url)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('verify'))


def confirm_login(redirect_uri):
    # Check for state and for 0 errors
    logging.info("Confirm login")
    state = session.get('oauth2_state')

    if request.values.get('error'):
        error = {
            'message': 'There was an error authenticating with Discord: {}'.format(request.values.get('error')),
            'link': {
                'text': 'Return home',
                'href': url_for('verify')
            }
        }
        return render_template('error.html', session=session, error=error)

    if not state or not request.args.get('code'):
        return False

    # Fetch token
    discord = make_discord_session(state=state, redirect_uri=redirect_uri)
    discord_token = discord.fetch_token(config.DISCORD_TOKEN_URL, client_secret=config.DISCORD_CLIENT_SECRET,
                                        authorization_response=request.url.replace('http:', 'https:'))

    if not discord_token:
        return redirect(url_for('verify'))

    # Fetch the user
    user = get_discord_user(discord_token)

    if 'status' in user:
        if user['status'] == 'error':
            return render_template('error.html', session=session, error=user)

    else:
        # Generate api_key from user_id
        logging.info("Secret key start")
        serializer = JSONWebSignatureSerializer(app.config['SECRET_KEY'])
        logging.info("Secret key end")
        api_key = str(serializer.dumps({'user_id': user['id']}))

        db.users.find_one_and_update(
            {"discord.id": user["id"]},
            {"$set": {
                "discord.api_key": api_key,
                "discord.token": discord_token
            }}
        )

        # Store api_token in client session
        discord_api_token = {
            'api_key': api_key,
            'user_id': user['id']
        }
        session.permanent = True
        session['discord_api_token'] = discord_api_token

        return user



def token_updater(discord_token):
    user = get_discord_user(discord_token)
    # Save the new discord_token
    db.users.find_one_and_update(
        {"reddit.id": session["reddit"]["id"]},
        {"$set": {"discord.token": discord_token}}
    )


def make_discord_session(token=None, state=None, scope=None, redirect_uri=None):
    return OAuth2Session(
        client_id=config.DISCORD_CLIENT_ID,
        token=token,
        state=state,
        scope=scope,
        redirect_uri=redirect_uri,
        auto_refresh_kwargs={
            'client_id': config.DISCORD_CLIENT_ID,
            'client_secret': config.DISCORD_CLIENT_SECRET,
        },
        auto_refresh_url=config.DISCORD_TOKEN_URL,
        token_updater=token_updater
    )


def make_reddit_session(token=None, state=None, scope=None):
    return OAuth2Session(
        client_id=config.REDDIT_CLIENT_ID,
        token=token,
        state=state,
        scope=scope,
        redirect_uri=config.REDDIT_REDIRECT_URL,
        auto_refresh_kwargs={
            'client_id': None,
            'client_secret': None,
        },
        auto_refresh_url=None,
        token_updater=None
    )


def get_discord_user(token):
    # If it's an api_token, go fetch the discord_token
    if token.get('api_key'):
        token = db.users.find_one({"discord.id": token['user_id']})['discord']['token']

    discord = make_discord_session(token=token)

    req = discord.get(config.DISCORD_API_BASE_URL + '/users/@me')
    if req.status_code != 200:
        abort(req.status_code)

    user = req.json()

    user["name"] = user["username"] + "#" + user["discriminator"]

    return user


def get_reddit_user(token):
    user = requests.get(config.REDDIT_OAUTH_BASE_URL + "/me",
                        headers={"Authorization": "bearer " + token, 'User-agent': 'hwsukverify'}).json()

    account_age = user['created'] < (dt.utcnow() + timedelta(-7)).timestamp()
    account_karma = user['comment_karma'] >= 0 or user['link_karma'] >= 0
    unbanned = not (any(checkBanR.subreddit('hardwareswapuk').banned(redditor=user['name'])))

    if account_age and account_karma and unbanned:
        # Save that to the db
        user = {k: v for (k, v) in user.items() if k in ["id", "name"]}

        # Only save the reddit instance if it doesnt already exist.
        # The users id and name never changes anyway.
        db.users.find_one_and_update(
            {"reddit.id": user["id"]},
            {"$setOnInsert": {
                "reddit": user,
                "verified": False,
                "role": False,
            }},
            upsert=True
        )

        # Save that to the session for easy template access
        session["reddit"] = user

        return user

    else:
        error = {"status": "error", "link": {
            "text": "Return home",
            "href": url_for('verify')
        }}
        if not account_age:
            error['message'] = "Sorry, your account does not meet the minimum age requirement - it must be at least 1 week old."
        elif not account_karma:
            error['message'] = "Sorry, your Reddit account must have comment and link karma before it can be linked."
        elif not unbanned:
            error['message'] = "Sorry, you are banned from /r/HardwareSwapUK. If you think this is in error, please send a modmail."
        return error


@app.before_request
def before_request():
    logging.debug(f'{request.method} {request.path} (handled by endpoint "{request.endpoint}")')


@app.errorhandler(exceptions.NotFound)
def handle_not_found(err):
    return render_template("error.html", error={
        "message": "The page you were looking for doesn't exist."}, session=session)


app.config["SECRET_KEY"] = config.FLASK_SECRET_KEY
