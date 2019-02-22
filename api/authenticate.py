# -*- coding: utf-8 -*-
import json

from bson import ObjectId
from flask import request, jsonify, make_response, session
from flask.views import MethodView

from api.authenticate_utils import requires_post_auth, verify_password, not_json_request, do_get_auth, \
    is_session_active, session_expired
from api.database import get_users, get_sessions, user_has_session, create_log, get_request_token, update_last_login, \
    find_user
from config.settings import LOG_USER_TYPE, SESSION_LIFETIME
from utils.util_functions import JSONEncoder, generate_token, make_date_time


class Api(MethodView):
    pass

def index():
    return make_response(jsonify({"error": 'Sorry You are not allowed to access this page...', "data": False}), 200)


def login():
    if not request.is_json or not (request.json.keys() & {"username", "password"}):
        return make_response(jsonify({"error": 'request is missing information', "data": False}), 200)

    username = request.json['username']
    password = request.json['password']
    if not username or not password:
        return make_response(jsonify({"error": 'required fields are not provided', "data": False}), 200)

    try:
        users = get_users()
        user = users.find_one({"$or": [{"username": username}, {"email": username}]})
        if not user:
            return make_response(jsonify({"error": 'Wrong username', "data": False}), 200)

        if not verify_password(password, user['password']):
            return make_response(jsonify({"error": 'Invalid user credentials', "data": False}))

        if 'status' not in user.keys() or not user['status'] == "active":
            return make_response(jsonify({"error": 'Access denied. User was deactivated.', "data": False}), 200)

        user['id'] = user['_id']
        del user['_id']
        del user['password']

        if user_has_session(user['id']):
            if is_session_active(user_id=user['id']):
                return make_response(jsonify({"error": False, "data": "already logged in",
                                              "token": get_request_token(user['id']), "user":
                                                  json.dumps(user, cls=JSONEncoder)}), 200)

            return session_expired()

        session['username'] = user['username']
        session['email'] = user['email']
        session['is_logged_in'] = True
        session['user_id'] = user['id']
        session['token'] = generate_token()
        session['expiration'] = make_date_time(SESSION_LIFETIME)

        update_last_login(user['email'])

        create_log(user, request, "Logged in", LOG_USER_TYPE)

    except IndexError:
        return make_response(jsonify({"error": 'No data found', "data": False}))
    return make_response(jsonify({"error": False, "token": session["token"], "data": json.dumps(user, cls=JSONEncoder)}))


def logout(user_id=None, token=None):
    f = do_get_auth(user_id, token)
    if not isinstance(f, bool):
        return f
    else:
        if f is not True:
            return make_response(jsonify({"error": 'Invalid User id.', "data": False}), 200)

    if not isinstance(user_id, ObjectId):
        if not user_id or not len(user_id) == 24:
            return make_response(jsonify({"error": 'Invalid User id.', "data": False}), 200)

    sessions = get_sessions()
    result = sessions.delete_many({"data.user_id": ObjectId(user_id)})
    session.clear()
    if result and result.deleted_count < 1:
        return make_response(jsonify({
            "error": "Could not log you out. The possible cause is due to invalid request data",
            "data": False
        }))

    return make_response(jsonify({"error": False, "data": True}))
