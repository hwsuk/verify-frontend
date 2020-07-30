#!/usr/bin/python3
import logging
import sys
import config
from app import app as application

application.secret_key = config.FLASK_SECRET_KEY
