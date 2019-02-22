# -*- coding: utf-8 -*-
from collections import namedtuple

from bson import ObjectId, CodecOptions
from pymongo import MongoClient, errors

from config.settings import MONGO_DBPASS, MONGO_HOST, MONGO_PORT, MONGO_DBNAME, MONGO_DBUSER, \
    MONGO_USER_COLLECTION, MONGO_SESSIONS_COLLECTION, MONGO_LOGS_COLLECTION, SESSION_LIFETIME, SYSTEM_EMAIL, SYSTEM_NAME
from utils.util_functions import make_date_time, generate_token


def get_mongodb_connection(collection=None):

    try:
        connection = MongoClient(host=MONGO_HOST, port=MONGO_PORT)
    except errors.ConnectionFailure:
        raise ValueError('Connection to server failed.')

    except errors.ServerSelectionTimeoutError:
        raise ValueError("Database Server is down. Please start it")

    else:
        db = connection.get_database(MONGO_DBNAME)
        if MONGO_DBUSER and MONGO_DBPASS:
            try:
                db.authenticate(name=MONGO_DBUSER, password=MONGO_DBPASS)
            except errors.OperationFailure:
                raise ValueError('Authentication to database {} failed'.format(MONGO_DBNAME))

        if collection is None:
            return db
        options = CodecOptions(tz_aware=True, )
        col = db.get_collection(collection, codec_options=options)
        col.ensure_index('_id')
        return col


def get_request_token(user_id):
    if not isinstance(user_id, ObjectId):
        if not len(user_id) == 24:
            return False
        user_id = ObjectId(user_id)
    sessions = get_sessions()
    user_session_one = sessions.find_one({"data.user_id": user_id})
    if not user_session_one:
        return False
    return user_session_one['data']['token']


def update_request_token(user_id):
    sessions = get_sessions()
    token = generate_token()
    if not isinstance(user_id, ObjectId):
        if not len(user_id) == 24:
            return False
        mt = sessions.find_one_and_update({"data.user_id": ObjectId(user_id)}, {"$set": {
            "data.token": token,
            "data.expiration": make_date_time(SESSION_LIFETIME)
        }}, upsert=False, return_document=True)
        if not mt:
            return False
    else:
        mt = sessions.find_one_and_update({"data.user_id": user_id}, {"$set": {
            "data.token": token,
            "data.expiration": make_date_time(SESSION_LIFETIME)
        }}, upsert=False, return_document=True)
        if not mt:
            return False
    return True


def find_user(_id=None, email=None):
    if _id and not isinstance(_id, ObjectId):
        if not len(_id) == 24:
            return False
        _id = ObjectId(_id)
    if _id and not email:
        return get_mongodb_connection(MONGO_USER_COLLECTION).find_one({"_id": _id})
    if email and not _id:
        return get_mongodb_connection(MONGO_USER_COLLECTION).find_one({"email": email})
    return get_mongodb_connection(MONGO_USER_COLLECTION).find_one({"_id": _id, "email": email})


def get_users():
    return get_mongodb_connection(MONGO_USER_COLLECTION)


def get_logs():
    return get_mongodb_connection(MONGO_LOGS_COLLECTION)


def get_sessions():
    return get_mongodb_connection(MONGO_SESSIONS_COLLECTION)


def user_has_session(user_id):
    if not isinstance(user_id, ObjectId):
        if not len(user_id) == 24:
            return False
        user_id = ObjectId(user_id)
    sessions = get_sessions()
    return sessions.find({"data.user_id": user_id}).count() > 0


def user_exists(email):
    users = get_mongodb_connection(MONGO_USER_COLLECTION)
    return users.find_one({"email": email})


def create_user(user_object):
    users = get_users()
    ins = users.insert_one(user_object)
    return ins.inserted_id


def deactivate_user_status(email):
    users = get_mongodb_connection(MONGO_USER_COLLECTION)
    return users.find_one_and_update({"email": email}, {"$set": {"status": "deactivated"}})


def activate_user_status(email):
    users = get_mongodb_connection(MONGO_USER_COLLECTION)
    return users.find_one_and_update({"email": email}, {"$set": {"status": "active"}})


def create_log(user, request, action, log_type):
    logs = get_logs()
    if not user:
        user = {"username": SYSTEM_NAME, "email": SYSTEM_EMAIL}
    if not request:
        request = namedtuple("request", ["path"])
        request.path = "/system"

    logs.insert({
        "username": user['username'],
        "email": user['email'],
        "accessUrl": request.path,
        "lastAccessTime": make_date_time(),
        "event": action,
        "type": log_type
    })


def update_last_login(email):
    users = get_mongodb_connection(MONGO_USER_COLLECTION)
    return users.find_one_and_update({"email": email}, {"$set": {"last_login": make_date_time()}}, upsert=True)
