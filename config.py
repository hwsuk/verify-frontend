import os
from datetime import datetime


def get_env(key, required=False, or_else=None):
    value = os.environ.get(key)

    if required and or_else:
        print(f"get_env(): for {key}, or_else parameter was ignored because this variable is required")

    if value is not None:
        return value
    else:
        if required:
            raise RuntimeError(f"Required environment variable {key} is missing.")
        else:
            return or_else


DB_HOST = get_env("MONGODB_HOST", or_else="127.0.0.1")
DB_PORT = get_env("MONGODB_PORT", or_else="27017")
DB_USERNAME = get_env("MONGODB_USERNAME", required=True)
DB_PASSWORD = get_env("MONGODB_PASSWORD", required=True)
DB_DATABASE = get_env("MONGODB_DATABASE", or_else="hwsuk")

DISCORD_CLIENT_ID = get_env("DISCORD_CLIENT_ID", required=True)
DISCORD_CLIENT_SECRET = get_env("DISCORD_CLIENT_SECRET", required=True)
DISCORD_REDIRECT_BASE_URL = get_env("DISCORD_REDIRECT_BASE_URL", or_else="https://verify.hardwareswap.uk")
DISCORD_API_BASE_URL = get_env("DISCORD_API_BASE_URL", or_else="https://discordapp.com/api")
DISCORD_AUTHORIZATION_URL = DISCORD_API_BASE_URL + '/oauth2/authorize'
DISCORD_TOKEN_URL = DISCORD_API_BASE_URL + '/oauth2/token'
DISCORD_WHITELISTED_SERVER_IDS = get_env("DISCORD_WHITELISTED_SERVER_IDS", required=True)

REDDIT_CLIENT_ID = get_env("REDDIT_CLIENT_ID", required=True)
REDDIT_CLIENT_SECRET = get_env("REDDIT_CLIENT_SECRET", required=True)
REDDIT_REDIRECT_URL = get_env("REDDIT_REDIRECT_URL", or_else="https://verify.hardwareswap.uk/login/reddit")
REDDIT_API_BASE_URL = get_env("REDDIT_API_BASE_URL", or_else="https://old.reddit.com/api/v1")
REDDIT_OAUTH_BASE_URL = get_env("REDDIT_OAUTH_BASE_URL", or_else="https://oauth.reddit.com/api/v1")

FLASK_SECRET_KEY = get_env("FLASK_SECRET_KEY", required=True)

PRAW_CLIENT_ID = get_env("PRAW_CLIENT_ID", required=True)
PRAW_CLIENT_SECRET = get_env("PRAW_CLIENT_SECRET", required=True)
PRAW_PASSWORD = get_env("PRAW_PASSWORD", required=True)
PRAW_USER_AGENT = get_env("PRAW_USER_AGENT",
                          or_else="Checks if users are banned for our synced discord and keeps flairs synced")
PRAW_USERNAME = get_env("PRAW_USERNAME", or_else="HWSUKMods")

LOGGING_FILENAME = get_env("LOGGING_FILENAME", or_else=f'verify-{datetime.now().strftime("%m-%d-%Y-%H%M%S")}.log')
