# -*- coding: utf-8 -*-
from flask import request, make_response, jsonify

from api.authenticate_utils import requires_post_auth, do_get_auth
from api.database import find_user, get_logs, create_log, get_request_token, update_request_token
from config.settings import LOG_SYSTEM_TYPE


def fetch_logs(user_id=None, log_type="user", token=None):
    """
    :param token:
    :param user_id
    :param log_type
    :return:
    """
    f = do_get_auth(user_id, token)
    if not isinstance(f, bool):
        return f
    else:
        if f is not True:
            return make_response(jsonify({"error": 'Invalid User id.', "data": False}), 200)

    logs = get_logs()
    try:
        user = find_user(_id=user_id)
        if user:
            create_log(user, request, "accessed " + log_type + " logs", LOG_SYSTEM_TYPE)

        data = logs.find({'type': log_type}, {'_id': 0}).sort("lastAccessTime", -1)
        if not data or data.count() < 1:
            return make_response(jsonify({"error": 'No logs found..', "token": get_request_token(user_id), "data": False}))

        data = [x for x in data]

    except IndexError:
        return make_response(jsonify({"error": 'No data found', "token": get_request_token(user_id), "data": False}))

    return make_response(jsonify({"error": False, "token": get_request_token(user_id), "data": data}))


def delete_logs(user_id, log_type="user", retain=None, token=None):
    """
    :param token:
    :param user_id
    :param log_type
    :param retain
    :rtype: object
    """
    f = do_get_auth(user_id, token)
    if not isinstance(f, bool):
        return f
    else:
        if f is not True:
            return make_response(jsonify({"error": 'Invalid User id.', "data": False}), 200)

    logs = get_logs()
    try:
        """
        To change this so that deleting is limited to certain date to use retain
        """
        data = logs.delete_many({'type': log_type, "lastAccessTime": {"$lt": "2018-04-03 19:33:53"}})
        if not data or data.deleted_count < 1:
            return make_response(jsonify({"error": 'Unable to delete records. No records found ',
                                          "token": get_request_token(user_id), "data": False}))

        user = find_user(_id=user_id)
        if user:
            create_log(user, request, "accessed " + log_type + " logs", LOG_SYSTEM_TYPE)

    except IndexError:
        return make_response(jsonify({"error": 'No data found for deletion', "token": get_request_token(user_id), "data": False}))

    return make_response(jsonify({"error": False, "token": get_request_token(user_id), "data": data.deleted_count}))
