# -*- coding: utf-8 -*-
from datetime import datetime
from functools import wraps

import bcrypt
from bson import ObjectId
from dateutil import parser
from flask import request, jsonify, session

from api.database import get_sessions, update_request_token, find_user


def authenticate():
    message = {
        'message': "Authenticate.",
        'error': "Request Is Not Authenticated.",
        'data': False
    }
    resp = jsonify(message)

    resp.status_code = 401
    # resp.headers['WWW-Authenticate'] = 'Basic realm="Example"'
    return resp


def session_expired():
    message = {
        'message': "Authenticate.",
        'error': "Your Session has timed out. Please login again.",
        'data': False
    }
    resp = jsonify(message)
    resp.status_code = 401
    return resp


def user_is_inactive():
    message = {
        'message': "Authenticate.",
        'error': "Your account is inactive please consult the administrator.",
        'data': False
    }
    resp = jsonify(message)
    return resp


def not_json_request():
    message = {
        'message': "Request.",
        'error': "Request format is not supported ",
        'data': False
    }
    resp = jsonify(message)
    resp.status_code = 200
    return resp


def cant_update_session():
    message = {
        'message': "Request.",
        'error': "Failed to update session ",
        'data': False
    }
    resp = jsonify(message)
    resp.status_code = 200
    return resp


def requires_post_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        if not request or not request.json:
            return not_json_request()

        if not is_authenticated(request):
            return authenticate()

        if not is_session_active(request):
            return session_expired()

        user_id = request.json['user_id']
        if not is_user_activated(user_id):
            return user_is_inactive()

        # if not update_request_token(user_id):
        #    return cant_update_session()

        return f(*args, **kwargs)

    return decorated


def is_authenticated(req):
    if not is_request_valid(req):
        return False
    user_id = None
    if req and req.json['user_id']:
        user_id = req.json['user_id']

    sessions = get_sessions()
    if not isinstance(user_id, ObjectId):
        if not user_id:
            return False
        if not len(user_id) == 24:
            return False
    user_session_one = sessions.find_one({"data.user_id": ObjectId(user_id)})
    if not user_session_one:
        return False

    user_session = user_session_one['data']
    if "token" not in user_session or not user_session['token']:
        return False
    elif not (user_session['token'] == req.json['token']):
        return False

    return user_session


def is_session_active(req=None, user_id=None):

    if req and request.json['user_id']:
        user_id = req.json['user_id']

    sessions = get_sessions()
    user_session_one = sessions.find_one({"data.user_id": ObjectId(user_id)})
    if not user_session_one:
        return False
    if 'expiration' not in user_session_one['data'] or not user_session_one['data']['expiration']:
        return False

    dat = user_session_one['data']['expiration']
    if not isinstance(dat, datetime):
        dat = parser.parse(user_session_one['data']['expiration'])
    if dat <= datetime.now():
        sessions.delete_many({"data.user_id": ObjectId(user_id)})
        session.clear()
        return False
    return True


def is_request_valid(req):
    if not req or not req.json:
        return False
    if "user_id" not in req.json.keys() or not req.json['user_id']:
        return False
    if "token" not in req.json.keys() or not req.json['token']:
        return False
    return True


def is_user_activated(user_id):
    user = find_user(user_id)
    if not user:
        return False
    if user['status'] == "active" and user['confirmed'] is True:
        return True
    return False


def hash_password(password):
    try:
        return bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt(12))
    except ValueError:
        return False


def verify_password(text, hashed):
    try:
        try:
            hashed = hashed.encode('utf8')
        except AttributeError:
            pass
        return bcrypt.checkpw(text.encode("utf8"), hashed)
    except ValueError:
        return False


def do_get_auth(user_id, token):
    if not is_get_authenticated(user_id, token):
        return authenticate()

    if not is_get_session_active(user_id, token):
        return session_expired()

    if not is_user_activated(user_id):
        return user_is_inactive()

    # if not update_request_token(user_id):
    #    return cant_update_session()

    return True


def is_get_authenticated(user_id, token):

    sessions = get_sessions()
    if not isinstance(user_id, ObjectId):
        if not user_id:
            return False
        if not len(user_id) == 24:
            return False
    user_session_one = sessions.find_one({"data.user_id": ObjectId(user_id)})
    if not user_session_one:
        return False

    user_session = user_session_one['data']
    if "token" not in user_session or not user_session['token']:
        return False
    elif not (user_session['token'] == token):
        return False

    return user_session


def is_get_session_active(user_id, token):
    sessions = get_sessions()
    user_session_one = sessions.find_one({"data.user_id": ObjectId(user_id)})
    if not user_session_one:
        return False
    if 'expiration' not in user_session_one['data'] or not user_session_one['data']['expiration']:
        return False

    dat = user_session_one['data']['expiration']
    if not isinstance(dat, datetime):
        dat = parser.parse(user_session_one['data']['expiration'])
    if dat <= datetime.now():
        sessions.delete_many({"data.user_id": ObjectId(user_id)})
        session.clear()
        return False
    return True
