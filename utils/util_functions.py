# -*- coding: utf-8 -*-
from datetime import datetime, timedelta
import time
import binascii

import os
import re
from bson import ObjectId
from flask import json, jsonify, request, current_app
from flask_mail import Message, Mail
from itsdangerous import URLSafeTimedSerializer

from config.settings import SECURITY_PASSWORD_SALT, SECRET_KEY, MAIL_DEFAULT_SENDER


def not_found(error=None):
    message = {
        'status': 404,
        'error': 'The requested url is `Not Found:` ' + request.url,
        'data': False,
    }
    resp = jsonify(message)
    resp.status_code = 404
    return resp


def make_date_time(seconds_to_add=None, seconds_to_subtract=None) -> str:
    if seconds_to_add is None and seconds_to_subtract is None:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    else:
        try:
            if seconds_to_add and not seconds_to_subtract:
                secs = int(seconds_to_add)
                return (datetime.now() + timedelta(seconds=secs)).strftime("%Y-%m-%d %H:%M:%S")
            elif seconds_to_subtract and not seconds_to_add:
                secs = int(seconds_to_subtract)
                return (datetime.now() - timedelta(seconds=secs)).strftime("%Y-%m-%d %H:%M:%S")
            else:
                return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class JSONEncoder(json.JSONEncoder):
    def default(self, o) -> str:
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


def generate_token() -> str:
    return binascii.hexlify(os.urandom(20)).decode()


def generate_confirmation_token(email) -> str:
    """
    :param email:
    :return:
    """
    serializer = URLSafeTimedSerializer(SECRET_KEY)
    return serializer.dumps(email, salt=SECURITY_PASSWORD_SALT)


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(SECRET_KEY)
    try:
        email = serializer.loads(token, max_age=expiration, salt=SECURITY_PASSWORD_SALT)
    except:
        return False
    return email


def validate_password(password, length) -> bool:
    if not isinstance(length, int):
        raise ValueError("length must be an integer")
    if length > len(password):
        return False
    return password.isalnum()


def validate(value=None, type_check=1) -> bool:
    """
    type_check takes integer values below,
    1: for only letters
    2: for digits only
    3: for alpha numeric
    :param value:
    :param type_check:
    :return boolean:
    """
    if not value:
        return value
    if not isinstance(type_check, int) or type_check > 3:
        raise ValueError("type_heck must be an integer less than 4")

    if type_check is 1:
        return value.isalpha()
    elif type_check is 2:
        return value.isdigit()
    elif type_check is 3:
        return value.isalnum()
    else:
        return False


def validate_ips(ip=None, network=None):
    if not ip and not network:
        return False, False

    if ip and not network and not isinstance(ip, str):
        return False, False

    if network and not ip and not isinstance(network, str):
        return False, False

    ip_regex = re.compile("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
    net_regex = re.compile("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$")
    if network:
        network = network.strip()
    if ip:
        ip = ip.strip()

    if network and len(network) is 0:
        network = False

    if ip and len(ip) is 0:
        ip = False

    if ip and not network:
        if ip_regex.match(ip):
            return ip, False

    elif network and not ip:
        if net_regex.match(network):
            return False, network

    elif network and ip:
        if not net_regex.match(network) or not ip_regex.match(ip):
            return False, False

        return ip, network

    return False, False


def validate_email(email) -> bool:
    pattern = re.compile("^[A-Za-z0-9.+_-]+@[A-Za-z0-9._-]+\.[a-zA-Z]*$")
    if not pattern.match(email):
        return False
    return True


def send_mail(receiver, mess):
    message = Message(
        subject="TIP-API Message",
        recipients=[receiver],
        sender=MAIL_DEFAULT_SENDER,
        html="<b><h3>THIS MESSAGE IS TIMED.</h3></b> <br >" + mess,
        charset="utf-8"
    )
    mail = Mail(current_app)
    try:
        mail.send(message)
    except Exception as e:
        print("Connection Error: " + str(e.with_traceback(None)))
        return False
    return True
