# -*- coding: utf-8 -*-
import json

from bson import ObjectId
from flask import make_response, jsonify, request
from flask_pymongo import ASCENDING

from api.authenticate_utils import requires_post_auth, hash_password, verify_password, not_json_request, do_get_auth
from api.database import user_exists, create_user, create_log, find_user, get_request_token, \
    deactivate_user_status, get_users, activate_user_status
from config.settings import LOG_USER_TYPE, EMAIL_CONFIRM_LINK
from utils.util_functions import validate, validate_password, validate_email, JSONEncoder, generate_confirmation_token, \
    confirm_token, make_date_time, send_mail


@requires_post_auth
def add_user():
    """
    :parameter: user_id: the user making the request
    :parameter: token: the user token for each request
    :param: request
    request: POST {first_name, last_name, email, username, password, password_verify, user_id, token}
    :return:
    """
    keys = ("username", "password", "password_verify", "first_name", "last_name", "email", "user_id")
    user_id = request.json['user_id']
    if not set(keys).issubset(set(request.json)):
        return make_response(jsonify({"error": 'Some fields are missing', "token": get_request_token(user_id),
                                      "data": False}), 200)

    username = request.json['username']
    password = request.json['password']
    password_verify = request.json['password_verify']

    email = request.json['email']
    first_name = request.json['first_name']
    last_name = request.json['last_name']

    if not validate(username, 1):
        return make_response(jsonify({"error": 'Username should only contain letters',
                                      "token": get_request_token(user_id), "data": False}), 200)

    if not validate_email(email):
        return make_response(jsonify({"error": "Email is invalid. ex. user@site.com",
                                      "token": get_request_token(user_id), "data": False}), 200)

    if user_exists(email):
        return make_response(jsonify({"error": "Email already in used. Use another email",
                                      "token": get_request_token(user_id), "data": False}), 200)

    if not password == password_verify:
        return make_response(jsonify({"error": 'Passwords do not match.', "token": get_request_token(user_id),
                                      "data": False}), 200)

    if not validate_password(password, 6):
        return make_response(jsonify({"error": 'Password should only be alphanumeric and min length 6',
                                      "token": get_request_token(user_id), "data": False}), 200)

    """
    Need to implement permissions on each user
    add permissions object/dict
    """
    conf_token = generate_confirmation_token(email)
    user_object = {
        "username": username,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "password": hash_password(password),
        "status": "pending",
        "confirmation_token": conf_token,
        "confirmed_on": "",
        "confirmed": False
    }

    mess = EMAIL_CONFIRM_LINK + conf_token + "/"
    mess = "<b style='color: blue'>Use this link to activate your account :</b> " \
           "<br> <br> <a href='" + mess + "' target='_blank' >" + mess + "</a>"
    if not send_mail(email, mess):
        return make_response(jsonify({"error": "Unable to create user, failed to send an email to this user. "
                                               "Cant connect to mail server.", "token": get_request_token(user_id),
                                      "data": False}), 200)

    if create_user(user_object):
        us = find_user(request.json['user_id'])
        create_log(us, request, "Added new user", LOG_USER_TYPE)
        return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                      "data": "New user has been created. User should confirm his/her"
                                              " email by visiting the link sent to him."}), 200)

    return make_response(jsonify({"error": "Something went wrong. Unable to create new user.",
                                  "token": get_request_token(user_id), "data": False}), 200)


def deactivate_user(email, user_id=None, token=None):
    """
    :parameter: user_id: the user making the request
    :parameter: email: the email of user to deactivate
    :parameter: token: the user token for each request
    :rtype: object
    """
    f = do_get_auth(user_id, token)
    if not isinstance(f, bool):
        return f
    else:
        if f is not True:
            return make_response(jsonify({"error": 'Invalid User id.', "data": False}), 200)

    email = email.replace('-', '@')
    if not validate_email(email):
        return make_response(jsonify({"error": "Email is invalid. ex. user@site.com",
                                      "token": get_request_token(user_id), "data": False}), 200)

    if deactivate_user_status(email):
        create_log(find_user(user_id), request, "deactivated an account of {0}".format(email), LOG_USER_TYPE)

        return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                      "data": "User has been deactivated successfully"}), 200)

    return make_response(jsonify({"error": "Sorry. Could not deactivate user. Something happened",
                                  "token": get_request_token(user_id), "data": False}), 200)


@requires_post_auth
def activate_user():
    """
    :parameter: user_id: the user making the request
    :parameter: email: the email of user to activate
    :parameter: token: the user token for each request
    :rtype: object
    """
    keys = ("email", "user_id")
    user_id = request.json['user_id']
    email = request.json['email']
    if not set(keys).issubset(set(request.json)):
        return make_response(jsonify({"error": 'Some fields are missing', "token": get_request_token(user_id),
                                      "data": False}), 200)

    if not validate_email(email):
        return make_response(jsonify({"error": "Email is invalid. ex. user@site.com",
                                      "token": get_request_token(user_id), "data": False}), 200)

    if activate_user_status(email):
        create_log(find_user(user_id), request, "Activated account of {0}".format(email), LOG_USER_TYPE)

        return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                      "data": "User has been activated successfully"}), 200)

    return make_response(jsonify({"error": "Sorry. Could not activate user. Something happened",
                                  "token": get_request_token(user_id), "data": False}), 200)


def fetch_all_users(user_id=None, token=None):
    """
    :parameter: user_id: the user making the request
    :parameter: token: the user token for each request
    :rtype: object
    """
    f = do_get_auth(user_id, token)
    if not isinstance(f, bool):
        return f
    else:
        if f is not True:
            return make_response(jsonify({"error": 'Invalid User id.', "data": False}), 200)
    users = get_users().find({})
    if users:
        users = users.sort([("status", ASCENDING), ("first_name", ASCENDING), ("last_name", ASCENDING)])

        user_list = []
        for x in users:
            x['id'] = x['_id']
            del x['_id']
            del x['password']
            user_list.append(x)

        create_log(find_user(user_id), request, "retrieved user data", LOG_USER_TYPE)
        return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                      "data": json.dumps(user_list, cls=JSONEncoder)}), 200)
    return make_response(jsonify({"error": False, "token": get_request_token(user_id), "data": False}), 200)


def fetch_single_user(user_email_id, user_id=None, token=None):
    """
    :parameter: user_id: the user making the request
    :parameter: token: the user token for each request
    :param: user_email_id: user id to update
    :rtype: object
    """
    f = do_get_auth(user_id, token)
    if not isinstance(f, bool):
        return f
    else:
        if f is not True:
            return make_response(jsonify({"error": 'Invalid User id.', "data": False}), 200)

    if not user_email_id or not len(user_email_id) == 24:
        return make_response(jsonify({"error": 'A valid User id is required', "token": get_request_token(user_id),
                                      "data": False}), 200)
    user = find_user(user_email_id)
    if user:
        user['id'] = user['_id']
        del user['_id']
        del user['password']

        create_log(find_user(user_id), request, "retrieved user data", LOG_USER_TYPE)
        return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                      "data": json.dumps(user, cls=JSONEncoder)}), 200)
    return make_response(jsonify({"error": "Could not find the requested user.", "token": get_request_token(user_id), "data": False}), 200)


@requires_post_auth
def update_user():
    """
    :parameter: request
    request {user_id, token, user:object}
    user: object{update_user_id, username, first_name, last_name, status }
    :return:
    """
    user_id = request.json['user_id']
    if "update_user_id" not in request.json:
        return make_response(jsonify({"error": "User update cannot be performed due to required missing "
                                               "field(update_user_id)", "token": get_request_token(user_id),
                                      "data": False}), 200)
    update_user_id = request.json['update_user_id']
    cond = ("username", "first_name", "last_name", "status")
    updates = {}
    for ob in cond:
        if ob in request.json:
            updates[ob] = request.json[ob]

    if not updates:
        return make_response(jsonify({"error": "Update was unsuccessful. No valid updates provided",
                                      "token": get_request_token(user_id), "data": False}), 200)

    if not find_user(update_user_id):
        return make_response(jsonify({"error": "Could not find the user you want to update",
                                      "token": get_request_token(user_id), "data": False}), 200)
    users = get_users()
    users.find_one_and_update({"_id": ObjectId(update_user_id)}, {"$set": updates}, upsert=True)
    return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                  "data": "User update has been successful."}), 200)


@requires_post_auth
def change_password():
    """
    :parameter: request
    request: {user_id, token, old_password, new_password, new_password_verify}
    :rtype: object
    """
    user_id = request.json['user_id']
    cond = ("old_password", "new_password", "new_password_verify")
    if not all(val in request.json.keys() for val in cond):
        return make_response(jsonify({"error": 'Some data was missing in the submitted request. ',
                                      "token": get_request_token(user_id),
                                      "data": False}), 200)
    user = find_user(user_id)
    if not user:
        return make_response(jsonify({"error": 'Could not find this user. Please logout and in again',
                                      "token": get_request_token(user_id),
                                      "data": False}), 200)

    if not request.json['new_password'] == request.json['new_password_verify']:
        return make_response(jsonify({"error": 'Passwords do not match.', "token": get_request_token(user_id),
                                      "data": False}), 200)

    if verify_password(request.json['old_password'], user['password']):
        get_users().update_one({"email": user['email']}, {"$set": {
            "password": hash_password(request.json['new_password'])}})

        create_log(find_user(user_id), request, "changed his password", LOG_USER_TYPE)
        return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                      "data": "Password change has been successful."}), 200)
    return make_response(
        jsonify({"error": "Old password is not valid. please correct it.", "token": get_request_token(user_id), "data": False}),
        200)


def confirm_email(token):
    """
    :param token
    :rtype: object
    """
    if not token:
        return make_response(jsonify({"error": "Confirmation link is invalid or has expired.", "data": False}), 200)
    email = confirm_token(token)
    users = get_users()
    user = users.find_one({"email": email})
    if user:
        if user['confirmed'] is True:
            return make_response(jsonify({"error": False, "token": get_request_token(user['_id']),
                                          "data": "Account already confirmed. Please login"}), 200)
        else:
            users.update_one({"email": email}, {"$set": {
                "status": "active", "confirmation_token": "", "confirmed": True, "confirmed_on": make_date_time()}})

            return make_response(jsonify({"error": False, "token": get_request_token(user['_id']),
                                          "data": "You have confirmed your account! Thanks"}), 200)

    return make_response(jsonify({"error": "Confirmation link is invalid or has expired.", "data": False}), 200)


def forgot_password(email):
    """
    :parameter: request
    request: {email}
    :return:
    """
    """
    if not request or not request.json:
        return not_json_request()

    if "email" not in request.json or not request.json['email']:
        return make_response(jsonify({"error": False, "token": "",
                                      "data": "Please provide your registered email"}), 200)
    email = request.json['email']
    """
    user = find_user(email=email)
    if not user:
        return make_response(jsonify({"error": "Wrong email is provided.", "token": "",
                                      "data": False}), 200)

    forgot_token = generate_confirmation_token(email=email)  # token to send to user
    get_users().find_one_and_update({"email": email}, {"$set": {"forgot_token": forgot_token}}, upsert=True)

    mess = "<b style='color: red'>This is the reset token you need to submit with your new password. TOKEN::</b> " \
           "<br> <br>" + forgot_token
    if not send_mail(email, mess):
        return make_response(jsonify({"error": "Unable to send an email to you. PCant connect to mail server",
                                      "token": "", "data": False}), 200)

    return make_response(jsonify({"error": False, "token": "",
                                  "data": "A reset token has been sent to you. please submit that link with the "
                                          "new password. The token expires in one hour."}), 200)


def confirm_password_reset():
    """
    request: {forgot__token, new_password, new_password_verify}
    :return:
    """
    if not request or not request.json:
        return not_json_request()
    cond = ("forgot_token", "new_password", "new_password_verify")
    if not all(val in request.json.keys() for val in cond):
        return make_response(jsonify({"error": 'Some data was missing in the submitted request. ',
                                      "token": "", "data": False}), 200)
    token = request.json['forgot_token']
    password = request.json['new_password']
    password_2 = request.json['new_password_verify']

    email = confirm_token(token)
    if not email:
        return make_response(jsonify({"error": 'This token has already expired. please request a new token',
                                      "token": "", "data": False}), 200)
    user = find_user(email=email)
    if not user or ("forgot_token" not in user) or not (user['forgot_token'] == token):
        return make_response(jsonify({"error": 'Could not find this user. The token you provided could be corrupt',
                                      "token": "", "data": False}), 200)

    if not password == password_2:
        return make_response(jsonify({"error": 'Passwords do not match.', "token": "", "data": False}), 200)

    update = get_users().find_one_and_update({"email": email}, {"$set": {
        "forgot_token": "", "password": hash_password(password)}})

    if update:
        create_log(find_user(email=email), request, "Reset his password", LOG_USER_TYPE)
        return make_response(jsonify({"error": False, "token": get_request_token(user['_id']),
                                      "data": "Password change has been successful. You can now login."}), 200)
    return make_response(
        jsonify({"error": "Password reset Failed. Consult the admin.", "token": "", "data": False}), 200)
