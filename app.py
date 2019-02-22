# -*- coding: utf-8 -*-
from flask import Flask
from flask_cors import CORS

from api.analysis.entry import main_function, RepeatingTimer
from config.settings import DEBUG, MONGO_DBNAME, MONGO_HOST, MONGO_PORT, MONGO_SESSIONS_COLLECTION, SECRET_KEY, \
    ENVIRONMENT, SESSION_LIFETIME, SECURITY_PASSWORD_SALT, HOST, PORT, TESTING, MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, \
    MAIL_PASSWORD, MAIL_USE_SSL, MAIL_USE_TLS, MAIL_SUPPRESS_SEND, MAIL_DEFAULT_SENDER, MAIL_DEBUG
from urls import generate_urls
from utils.mongo_session import MongoSessionInterface
from utils.util_functions import not_found

app = Flask(__name__)
app.debug = DEBUG
app.testing = TESTING
app.secret_key = SECRET_KEY
app.config['SECURITY_PASSWORD_SALT'] = SECURITY_PASSWORD_SALT
app.errorhandler(404)(not_found)
app.env = ENVIRONMENT

app.config['PERMANENT_SESSION_LIFETIME'] = SESSION_LIFETIME
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_NAME'] = "TIP-API"

app.config['MAIL_SERVER'] = MAIL_SERVER
app.config['MAIL_PORT'] = MAIL_PORT
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
app.config['MAIL_USE_SSL'] = MAIL_USE_SSL
app.config['MAIL_DEFAULT_SENDER'] = MAIL_DEFAULT_SENDER
app.config['MAIL_DEBUG'] = MAIL_DEBUG
app.config['MAIL_SUPPRESS_SEND'] = MAIL_SUPPRESS_SEND

app.session_interface = MongoSessionInterface(
    host=MONGO_HOST,
    db=MONGO_DBNAME,
    port=MONGO_PORT,
    collection=MONGO_SESSIONS_COLLECTION
)
CORS(app)
generate_urls(app)

if __name__ == '__main__':

    t = RepeatingTimer(30, main_function)  # 5*60 in seconds
    t.start()  # every 5 mins, call main_function

    app.run(debug=DEBUG, host=HOST, port=PORT)
