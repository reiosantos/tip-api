import json

from flask import request, make_response, jsonify
from flask_pymongo import ASCENDING, DESCENDING

from api.analysis.database import get_blocked_by_ip, get_blocked_by_network, get_warned_by_ip, get_warned_by_network, \
    get_plots, save_settings, get_settings, get_domains
from api.analysis.post_actions_handler import unblock_all, block_all, get_new_global_alerts, get_new_local_alerts, \
    redirect_domain, remove_redirected_domain
from api.authenticate_utils import requires_post_auth, do_get_auth
from api.database import get_request_token, find_user, create_log
from config.settings import LOG_USER_TYPE
from utils.util_functions import JSONEncoder, validate_ips


def blocked_or_warned(category=None, order=None, user_id=None, token=None):
    """
    :param token:
    :param user_id:
    :param category: category of analysis ie blocked/(unblocked/warned)
    :param order: order of the category: ie network or ip
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
    if not category or not order:
        return make_response(jsonify({"error": False, "token": get_request_token(user_id), "data": False}), 200)

    ips = None
    if category == "warned" or category == "unblocked":
        if order == "ip":
            ips = get_warned_by_ip().find({})
        elif order == "network":
            ips = get_warned_by_network().find({})
    elif category == "blocked":
        if order == "ip":
            ips = get_blocked_by_ip().find({})
        elif order == "network":
            ips = get_blocked_by_network().find({})

    if ips:
        ibl = ips.sort([("block_date", DESCENDING), ("attempts", ASCENDING)])
        ibl_list = []
        for x in ibl:
            x['id'] = x['_id']
            del x['_id']
            ibl_list.append(x)

        create_log(find_user(user_id), request, "retrieved analysis data", LOG_USER_TYPE)
        return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                      "data": json.dumps(ibl_list, cls=JSONEncoder)}), 200)
    return make_response(jsonify({"error": False, "token": get_request_token(user_id), "data": False}), 200)


def get_plot_data(user_id=None, token=None):
    """
    :param: category of analysis ie blocked/(unblocked/warned)
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

    ips = get_plots().find({})
    if ips:
        ibl_list = []
        for x in ips:
            x['id'] = x['_id']
            del x['_id']
            ibl_list.append(x)

        create_log(find_user(user_id), request, "retrieved analysis data", LOG_USER_TYPE)
        return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                      "data": json.dumps(ibl_list, cls=JSONEncoder)}), 200)
    return make_response(jsonify({"error": False, "token": get_request_token(user_id), "data": False}), 200)


@requires_post_auth
def block_ip():
    user_id = request.json['user_id']
    if "data" not in request.json:
        return make_response(jsonify({"error": 'No data sent to server', "token": get_request_token(user_id),
                                      "data": False}), 200)
    data = request.json['data']
    if not isinstance(data, dict):
        return make_response(jsonify({"error": 'Data is not json formatted.', "token": get_request_token(user_id),
                                      "data": False}), 200)
    keys = ("ip", "network")
    if not set(keys).issubset(set(data)):
        return make_response(jsonify({"error": 'the data submitted must contain both the `ip` and `network` fields ',
                                      "token": get_request_token(user_id), "data": False}), 200)

    ip, network = validate_ips(ip=data['ip'], network=data['network'])
    if not ip or not network:
        return make_response(jsonify({"error": 'Invalid address has been forwarded. please check your data.',
                                      "token": get_request_token(user_id), "data": False}), 200)

    net_data = get_warned_by_network().find_one({"source_ip": ip, "source_network": network})
    feed = []
    if net_data and len(net_data) > 0:
        feed.clear()
        feed.append(net_data)
        block_all(networks=feed)

    else:
        ip_data = get_warned_by_ip().find_one({"source_ip": ip, "source_network": network})
        if ip_data and len(ip_data) > 0:
            feed.clear()
            feed.append(ip_data)
            block_all(ips=feed)
        else:
            return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                          "data": "Cant find this record. Unable to take action on the provided data."}), 200)

    return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                  "data": "Address has been black-listed "}), 200)


@requires_post_auth
def unblock_ip():
    user_id = request.json['user_id']
    if "data" not in request.json:
        return make_response(jsonify({"error": 'no data sent to server', "token": get_request_token(user_id),
                                      "data": False}), 200)
    data = request.json['data']
    if not isinstance(data, dict):
        return make_response(jsonify({"error": 'Data is not json formatted.', "token": get_request_token(user_id),
                                      "data": False}), 200)
    keys = ("ip", "network")
    if not set(keys).issubset(set(data)):
        return make_response(jsonify({"error": 'the data submitted must contain both the `ip` and `network` fields ',
                                      "token": get_request_token(user_id), "data": False}), 200)

    ip, network = validate_ips(ip=data['ip'], network=data['network'])
    if not ip or not network:
        return make_response(jsonify({"error": 'Invalid address has been forwarded. please check your data.',
                                      "token": get_request_token(user_id), "data": False}), 200)

    net_data = get_blocked_by_network().find_one({"source_ip": ip, "source_network": network})
    feed = []
    if net_data and len(net_data) > 0:
        feed.clear()
        feed.append(net_data)
        unblock_all(ips=feed)

    else:
        ip_data = get_blocked_by_ip().find_one({"source_ip": ip, "source_network": network})
        if ip_data and len(ip_data) > 0:
            feed.clear()
            feed.append(ip_data)
            unblock_all(ips=feed)
        else:
            return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                          "data": "Unable to take action on the provided data."}), 200)

    return make_response(jsonify({"error": False,
                                  "token": get_request_token(user_id), "data": "Address has been white-listed "}), 200)


def unblock_by_country(country=None, user_id=None, token=None):
    f = do_get_auth(user_id, token)
    if not isinstance(f, bool):
        return f
    else:
        if f is not True:
            return make_response(jsonify({"error": 'Invalid User id.', "data": False}), 200)

    if not country or not len(country.strip()) == 2:
        return make_response(jsonify({"error": 'Incorrect data sent to server', "token": get_request_token(user_id),
                                      "data": False}), 200)

    unblock_all(by_country=country)

    return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                  "data": "country `{0}` has been white-listed".format(country)}), 200)


def block_by_country(country=None, user_id=None, token=None):
    f = do_get_auth(user_id, token)
    if not isinstance(f, bool):
        return f
    else:
        if f is not True:
            return make_response(jsonify({"error": 'Invalid User id.', "data": False}), 200)

    if not country or not len(country.strip()) == 2:
        return make_response(jsonify({"error": 'Incorrect data sent to server', "token": get_request_token(user_id),
                                      "data": False}), 200)

    block_all(by_country=country)

    return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                  "data": "Country `{0}` has been black-listed ".format(country)}), 200)


@requires_post_auth
def block_network():
    user_id = request.json['user_id']
    if "network" not in request.json:
        return make_response(jsonify({"error": 'Incorrect data sent to server. network value is missing',
                                      "token": get_request_token(user_id),
                                      "data": False}), 200)

    ip, network = validate_ips(network=request.json['network'])

    if not network:
        return make_response(jsonify({"error": 'Invalid network address', "token": get_request_token(user_id),
                                      "data": False}), 200)

    fn = get_warned_by_ip().find({"source_network": network})
    if fn and fn.count() > 0:
        block_all(ips=list(fn))

    fn_2 = get_warned_by_network().find({"source_network": network})
    if fn_2 and fn_2.count() > 0:
        block_all(networks=list(fn_2))

    return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                  "data": "Network `{0}` has been black-listed ".format(network)}), 200)


@requires_post_auth
def unblock_network():
    user_id = request.json['user_id']
    if "network" not in request.json:
        return make_response(jsonify({"error": 'Incorrect data sent to server. network value is missing',
                                      "token": get_request_token(user_id),
                                      "data": False}), 200)

    ip, network = validate_ips(network=request.json['network'])

    if not network:
        return make_response(jsonify({"error": 'Invalid network address', "token": get_request_token(user_id),
                                      "data": False}), 200)

    fn = get_blocked_by_ip().find({"source_network": network})
    if fn and fn.count() > 0:
        unblock_all(ips=list(fn))

    fn_2 = get_blocked_by_network().find({"source_network": network})
    if fn_2 and fn_2.count() > 0:
        unblock_all(ips=list(fn_2))

    return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                  "data": "Network `{0}` has been white-listed ".format(network)}), 200)


def get_local_notifications(user_id=None, token=None):
    """
    :param: category of analysis ie blocked/(unblocked/warned)
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

    ips = get_new_local_alerts()

    return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                  "data": json.dumps(ips, cls=JSONEncoder)}), 200)


def get_global_notifications(user_id=None, token=None):
    """
    :param: category of analysis ie blocked/(unblocked/warned)
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

    ips = get_new_global_alerts()

    return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                  "data": json.dumps(ips, cls=JSONEncoder)}), 200)


@requires_post_auth
def update_settings():
    user_id = request.json['user_id']
    if "settings" not in request.json:
        return make_response(jsonify({"error": 'Incorrect data sent to server. settings are missing',
                                      "token": get_request_token(user_id),
                                      "data": False}), 200)

    settings = request.json['settings']
    if not isinstance(settings, dict):
        return make_response(jsonify({"error": 'a settings dictionary was expected but got {0}'.format(type(settings)),
                                      "token": get_request_token(user_id), "data": False}), 200)

    res = save_settings(settings)
    if not res:
        return make_response(jsonify({"error": "Could not update settings. Try again later",
                                      "token": get_request_token(user_id), "data": False}), 200)

    return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                  "data": "Settings have been updated successfully."}), 200)


def fetch_settings(user_id, token):
    """
    :param: category of analysis ie blocked/(unblocked/warned)
    :parameter: user_id: the user making the request
    :parameter: token: the user token for each request
    :rtype: object
    """
    f = do_get_auth(user_id, token)
    if not isinstance(f, bool):
        return f
    else:
        if f is not True:
            return make_response(jsonify({"error": 'Invalid User id or token', "data": False}), 200)

    ips = get_settings()
    data = []
    for d in ips:
        data.append(d)
    return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                  "data": json.dumps(data, cls=JSONEncoder)}), 200)


@requires_post_auth
def redirect_domain_handle():
    user_id = request.json['user_id']
    if "domain" not in request.json:
        return make_response(jsonify({"error": 'Incorrect data sent to server. domain is missing',
                                      "token": get_request_token(user_id),
                                      "data": False}), 200)

    domain = request.json['domain']

    res = get_domains().find_one_and_update({"_id": domain}, {"redirected": True})
    if not res:
        return make_response(jsonify({"error": "Could not find the domain specified.",
                                      "token": get_request_token(user_id), "data": False}), 200)
    redirect_domain(domain)

    return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                  "data": "Domain {0} has been zoned for redirection.".format(domain)}), 200)


@requires_post_auth
def remove_redirected_domain_handle():
    user_id = request.json['user_id']
    if "domain" not in request.json:
        return make_response(jsonify({"error": 'Incorrect data sent to server. domain is missing',
                                      "token": get_request_token(user_id),
                                      "data": False}), 200)

    domain = request.json['domain']

    res = get_domains().find_one_and_update({"_id": domain}, {"$set": {"redirected": False}}, upsert=True)
    if not res or res['redirected']:
        return make_response(jsonify({"error": "Could not remove the domain specified.",
                                      "token": get_request_token(user_id), "data": False}), 200)

    remove_redirected_domain(domain)

    return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                  "data": "Domain {0} has been zoned for redirection.".format(domain)}), 200)


def fetch_domains(user_id, token):
    """
    :param: category of analysis ie blocked/(unblocked/warned)
    :parameter: user_id: the user making the request
    :parameter: token: the user token for each request
    :rtype: object
    """
    f = do_get_auth(user_id, token)
    if not isinstance(f, bool):
        return f
    else:
        if f is not True:
            return make_response(jsonify({"error": 'Invalid User id or token', "data": False}), 200)

    ips = get_domains().find()
    data = []
    for d in ips:
        data.append(d)
    return make_response(jsonify({"error": False, "token": get_request_token(user_id),
                                  "data": json.dumps(data, cls=JSONEncoder)}), 200)
