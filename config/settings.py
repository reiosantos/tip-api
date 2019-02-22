# -*- coding: utf-8 -*-
"""
Server and Database configurations
"""
import os

from dotenv import load_dotenv

load_dotenv()

MONGO_HOST = os.getenv('MONGO_HOST')
MONGO_PORT = int(os.getenv('MONGO_PORT', 27017))
MONGO_DBNAME = os.getenv('MONGO_DBNAME')
MONGO_DBUSER = os.getenv('MONGO_DBUSER')
MONGO_DBPASS = os.getenv('MONGO_DBPASS')

MONGO_DEFAULT_COLLECTION = '_default'
MONGO_SETTINGS_COLLECTION = 'settings'
MONGO_USER_COLLECTION = 'users'
MONGO_FEEDS_COLLECTION = 'feeds'
MONGO_LOGS_COLLECTION = 'logs'
MONGO_SESSIONS_COLLECTION = 'sessions'
MONGO_BLOCKED_IP_COLLECTION = "blocked_by_ip"
MONGO_BLOCKED_NETWORK_COLLECTION = "blocked_by_network"
MONGO_WARNING_IP_COLLECTION = "warned_by_ip"
MONGO_WARNING_NETWORK_COLLECTION = "warned_by_network"
MONGO_PLOTS_COLLECTION = "plots"
MONGO_DOMAINS_COLLECTION = "domains"

HOST = "0.0.0.0"
PORT = "5000"

EMAIL_CONFIRM_LINK = "http://" + HOST + ":" + PORT + "/api/user/confirm/"

SECRET_KEY = os.getenv('SECRET_KEY')
SECURITY_PASSWORD_SALT = os.getenv('SECURITY_PASSWORD_SALT')
SESSION_TYPE = 'mongodb'
SESSION_LIFETIME = 2*60*60  # life of a session is 2 hours(measured in seconds)

LOG_USER_TYPE = "user"
LOG_SYSTEM_TYPE = "system"
SYSTEM_NAME = "TIP-System"
SYSTEM_EMAIL = "noreply@tipapi.com"

DEBUG = True
TESTING = False
ENVIRONMENT = os.getenv('ENVIRONMENT')

MAIL_SERVER = 'smtp.gmail.com'  # 'smtp.googlemail.com'
MAIL_PORT = 465  # 587
MAIL_USE_TLS = False  # True
MAIL_USE_SSL = True  # False
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

MAIL_DEFAULT_SENDER = MAIL_USERNAME
MAIL_SUPPRESS_SEND = TESTING
MAIL_DEBUG = DEBUG

MAIL_MAX_EMAILS = None
MAIL_ASCII_ATTACHMENTS = False
