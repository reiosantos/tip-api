import threading

import subprocess
from netifaces import ifaddresses, AF_INET

import ipcalc

from api.analysis.database import get_settings

"""
Configurations for data analysis
should only be changed via the web interface, 
these are the default configs.
They serve as the base in case user has not set any configs  
"""

DNS_REDIRECT_TO_ADDRESS = "127.0.0.1"
KEY_DNS_REDIRECT_TO_ADDRESS = "DNS_REDIRECT_TO_ADDRESS"

MAX_ATTEMPTS_TO_BLOCK_IP = 2
KEY_MAX_ATTEMPTS_TO_BLOCK_IP = "MAX_ATTEMPTS_TO_BLOCK_IP"

MAX_ATTEMPTS_TO_WARN_IP = 1
KEY_MAX_ATTEMPTS_TO_WARN_IP = "MAX_ATTEMPTS_TO_WARN_IP"
# min minutes for attacker to be declared as a threat (0 mins) after the first attack
MINUTES_BEFORE_IP_IS_BLOCKED = 0
KEY_MINUTES_BEFORE_IP_IS_BLOCKED = "MINUTES_BEFORE_IP_IS_BLOCKED"
# max minutes for an attacker to be declared harmless (1 day) after the initial attack
MINUTES_BEFORE_IP_IS_UNBLOCKED = 24 * 60
KEY_MINUTES_BEFORE_IP_IS_UNBLOCKED = "MINUTES_BEFORE_IP_IS_UNBLOCKED"

MAX_MINUTES_TO_KEEP_A_FEED = 60 * 24 * 60  # 2 months
KEY_MAX_MINUTES_TO_KEEP_A_FEED = "MAX_MINUTES_TO_KEEP_A_FEED"

AUTO_UNBLOCKING_ENABLED = True
KEY_AUTO_UNBLOCKING_ENABLED = "AUTO_UNBLOCKING_ENABLED"

AUTO_BLOCKING_ENABLED = True
KEY_AUTO_BLOCKING_ENABLED = "AUTO_BLOCKING_ENABLED"

AUTO_DNS_REDIRECTION_ENABLED = True
KEY_AUTO_DNS_REDIRECTION_ENABLED = "AUTO_DNS_REDIRECTION_ENABLED"

AUTO_CLEAR_OLD_RECORDS_ENABLED = False
KEY_AUTO_CLEAR_OLD_RECORDS_ENABLED = "AUTO_CLEAR_OLD_RECORDS_ENABLED"

DNS_RECORD_REDIRECTION_COUNT = 4
KEY_DNS_RECORD_REDIRECTION_COUNT = "DNS_RECORD_REDIRECTION_COUNT"

MINUTES_A_RECORD_REMAINS_NEW = 10 * 24 * 60  # for ten days
KEY_MINUTES_A_RECORD_REMAINS_NEW = "MINUTES_A_RECORD_REMAINS_NEW"

default_settings = {
    KEY_DNS_REDIRECT_TO_ADDRESS: DNS_REDIRECT_TO_ADDRESS,
    KEY_MAX_ATTEMPTS_TO_BLOCK_IP: MAX_ATTEMPTS_TO_BLOCK_IP,
    KEY_MAX_ATTEMPTS_TO_WARN_IP: MAX_ATTEMPTS_TO_WARN_IP,
    KEY_MINUTES_BEFORE_IP_IS_BLOCKED: MINUTES_BEFORE_IP_IS_BLOCKED,
    KEY_MINUTES_BEFORE_IP_IS_UNBLOCKED: MINUTES_BEFORE_IP_IS_UNBLOCKED,
    KEY_MAX_MINUTES_TO_KEEP_A_FEED: MAX_MINUTES_TO_KEEP_A_FEED,
    KEY_AUTO_UNBLOCKING_ENABLED: AUTO_UNBLOCKING_ENABLED,
    KEY_AUTO_BLOCKING_ENABLED: AUTO_BLOCKING_ENABLED,
    KEY_AUTO_CLEAR_OLD_RECORDS_ENABLED: AUTO_CLEAR_OLD_RECORDS_ENABLED,
    KEY_MINUTES_A_RECORD_REMAINS_NEW: MINUTES_A_RECORD_REMAINS_NEW,
    KEY_AUTO_DNS_REDIRECTION_ENABLED: AUTO_DNS_REDIRECTION_ENABLED,
    KEY_DNS_RECORD_REDIRECTION_COUNT: DNS_RECORD_REDIRECTION_COUNT,
}

IPTABLES_BLOCK_RULE = "iptables -A TIP -s {0} -j DROP"
IPTABLES_UNBLOCK_RULE = "iptables -D TIP -s {0} -j DROP"
SUDO_PASSWORD = "santos"

lock = threading.Lock()

"""
plots variables to be used as keys in database
"""
CLASSIFICATION_TABLE = "classification_table"
ATTACK_BY_TYPE = "attack_by_type_bar_graph"
ATTACK_BY_IP = "attack_by_ip"
ATTACK_BY_NETWORK = "attack_by_network"
ATTACK_BY_ASN = "attack_by_asn"
ATTACK_BY_LOCATION = "attack_by_location"
ATTACK_BY_DATES = "attack_by_dates"
ATTACK_BY_TYPE_AGAINST_DATES_SERIES = "attack_by_type_date_series_graph"
ATTACK_PER_DAY_HOUR = "attack_per_hour"


def get_redirection_address():
    return get_settings(KEY_DNS_REDIRECT_TO_ADDRESS)


def ip_max_attempts_to_warn():
    return get_settings(KEY_MAX_ATTEMPTS_TO_WARN_IP)


def ip_max_attempts_to_block():
    return get_settings(KEY_MAX_ATTEMPTS_TO_BLOCK_IP)


def minutes_before_ip_is_blocked():
    return get_settings(KEY_MINUTES_BEFORE_IP_IS_BLOCKED)


def minutes_before_ip_is_unblocked():
    return get_settings(KEY_MINUTES_BEFORE_IP_IS_UNBLOCKED)


def minutes_a_record_remains_new():
    return get_settings(KEY_MINUTES_A_RECORD_REMAINS_NEW)


def minutes_to_keep_feed():
    return get_settings(KEY_MAX_MINUTES_TO_KEEP_A_FEED)


def redirection_count():
    return get_settings(KEY_DNS_RECORD_REDIRECTION_COUNT)


def is_auto_unblocking_enabled():
    v = get_settings(KEY_AUTO_UNBLOCKING_ENABLED)
    if not isinstance(v, bool):
        return False
    return v


def is_auto_blocking_enabled():
    v = get_settings(KEY_AUTO_BLOCKING_ENABLED)
    if not isinstance(v, bool):
        return False
    return v


def is_auto_clear_old_records_enabled():
    v = get_settings(KEY_AUTO_CLEAR_OLD_RECORDS_ENABLED)
    if not isinstance(v, bool):
        return False
    return v


def is_auto_redirection_enabled():
    v = get_settings(KEY_AUTO_DNS_REDIRECTION_ENABLED)
    if not isinstance(v, bool):
        return False
    return v


def my_ip_details():
    """
    :return: dictionary, with {address, netmask, broadcast, network}
    """
    i_face = subprocess.Popen("route | grep '^default' | grep -o '[^ ]*$'", shell=True, stdout=subprocess.PIPE,
                              universal_newlines=True).stdout.read()
    print('-----', i_face)

    if not i_face:
        return None
    i_face = i_face.split("\n")
    if len(i_face) > 0:
        i_face = i_face[0].strip()

    ip4_address = ifaddresses(i_face).setdefault(AF_INET, [{'addr': None}])
    if not ip4_address or len(ip4_address) == 0:
        return None
    try:
        ip4_address = ip4_address[0]
        tmp = ipcalc.IP(ip=ip4_address['addr'], mask=ip4_address['netmask'])
        ip4_address['network'] = str(tmp.guess_network())
        ip4_address['address'] = ip4_address['addr']
        ip4_address['interface'] = i_face
        del ip4_address['addr']
        return ip4_address
    except:
        print("unable to fetch connection details")
        return None
