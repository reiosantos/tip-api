#! /usr/bin/env python3
import json

import os
import subprocess
import threading

from dateutil import parser
from flask_pymongo import DESCENDING

from api.analysis.config import lock, minutes_before_ip_is_unblocked, minutes_to_keep_feed, is_auto_unblocking_enabled, \
    is_auto_clear_old_records_enabled, minutes_a_record_remains_new, my_ip_details, SUDO_PASSWORD, IPTABLES_BLOCK_RULE, \
    IPTABLES_UNBLOCK_RULE, is_auto_redirection_enabled, redirection_count, get_redirection_address
from api.analysis.database import get_blocked_by_ip, get_warned_by_ip, get_warned_by_network, get_blocked_by_network, \
    get_feeds, get_domains
from api.analysis.normalize_data import normalize_dict
from api.database import create_log
from config.settings import LOG_SYSTEM_TYPE
from utils.util_functions import make_date_time


def block_all(ips=None, networks=None, by_country=None):
    """
    :param by_country: string eg 'US'
    :param ips :{as format: [{document}, {document}...]}
    :param networks :{as format: [{document}, {document}...]}
    :rtype: object
    """
    if ips is None:
        ips = []
    if networks is None:
        networks = []
    if not ips and not networks and not by_country:
        return

    lock.acquire()

    blocked_collection = get_blocked_by_ip()
    warning_collection = get_warned_by_ip()
    n_blocked_collection = get_blocked_by_network()
    n_warning_collection = get_warned_by_network()

    if ips:
        for threat in ips:
            ip = threat['source_ip'] or None
            network = threat['source_network'] or None
            if ip:
                if '_id' in threat:
                    del threat['_id']
                threat['block_date'] = make_date_time()
                threat['unblock_date'] = ""
                blocked_collection.find_one_and_update({"source_ip": ip, "source_network": network},
                                                       {"$set": threat}, upsert=True)
                warning_collection.find_one_and_delete({"source_ip": ip, "source_network": network})

                threading.Thread(target=__do_the_actual_blocking, kwargs={'ip': ip}, daemon=True).start()

    if networks:
        for threat in networks:
            ip = threat['source_ip']
            network = threat['source_network']
            if network:
                if '_id' in threat:
                    del threat['_id']
                threat['block_date'] = make_date_time()
                threat['unblock_date'] = ""
                n_blocked_collection.find_one_and_update({"source_ip": ip, "source_network": network},
                                                         {"$set": threat}, upsert=True)
                n_warning_collection.find_one_and_delete({"source_ip": ip, "source_network": network})

                threading.Thread(target=__do_the_actual_blocking, kwargs={'network': network}, daemon=True).start()

    if by_country:
        records = blocked_collection.find({"source_geolocation_cc": by_country})
        if not records:
            records_2 = warning_collection.find({"source_geolocation_cc": by_country})
            if records_2:
                for rec in records_2:
                    if '_id' in rec:
                        del rec['_id']
                    rec['block_date'] = make_date_time()
                    rec['unblock_date'] = ""
                    blocked_collection.insert_one(rec)

                    threading.Thread(target=__do_the_actual_blocking, kwargs={'ip': rec['source_ip']},
                                     daemon=True).start()

                warning_collection.delete_many({"source_geolocation_cc": by_country})

        records_1 = n_blocked_collection.find({"source_geolocation_cc": by_country})
        if not records_1:
            records_2 = n_warning_collection.find({"source_geolocation_cc": by_country})
            if records_2:
                for rec in records_2:
                    if '_id' in rec:
                        del rec['_id']
                    rec['block_date'] = make_date_time()
                    rec['unblock_date'] = ""
                    n_blocked_collection.insert_one(rec)

                    threading.Thread(target=__do_the_actual_blocking, kwargs={'network': rec['source_network']},
                                     daemon=True).start()

                n_warning_collection.delete_many({"source_geolocation_cc": by_country})

    lock.release()


def unblock_all(ips=None, by_country=None):
    """
    :param by_country: country name/geolocation to unblock eg 'US'
    :param ips :{as format: [{source_ip, source_network}, ...]}
    :rtype: object
    """
    if not ips and not by_country:
        return

    lock.acquire()

    blocked_collection = get_blocked_by_ip()
    warning_collection = get_warned_by_ip()
    n_blocked_collection = get_blocked_by_network()
    n_warning_collection = get_warned_by_network()
    if ips:
        for ip in ips:
            i_p = ip['source_ip']
            net = ip['source_network']
            record = blocked_collection.find_one_and_delete({"source_ip": i_p, "source_network": net})
            if record:
                if '_id' in record:
                    del record['_id']
                record['block_date'] = ""
                record['unblock_date'] = make_date_time()
                warning_collection.find_one_and_update({"source_ip": i_p}, {"$set": record}, upsert=True)

                threading.Thread(target=__do_the_actual_unblocking, kwargs={'ip': i_p}, daemon=True).start()
            else:
                record = n_blocked_collection.find_one_and_delete({"source_ip": i_p, "source_network": net})
                if record:
                    if '_id' in record:
                        del record['_id']
                    record['block_date'] = ""
                    record['unblock_date'] = make_date_time()
                    n_warning_collection.find_one_and_update({"source_network": net}, {"$set": record}, upsert=True)

                    threading.Thread(target=__do_the_actual_unblocking, kwargs={'network': net}, daemon=True).start()

    if by_country:
        records = blocked_collection.find({"source_geolocation_cc": by_country})
        if records:
            for rec in records:
                if '_id' in rec:
                    del rec['_id']
                rec['block_date'] = ""
                rec['unblock_date'] = make_date_time()
                warning_collection.insert_one(rec)

                threading.Thread(target=__do_the_actual_unblocking, kwargs={'ip': rec['source_ip']},
                                 daemon=True).start()

            blocked_collection.delete_many({"source_geolocation_cc": by_country})

        records_1 = n_blocked_collection.find({"source_geolocation_cc": by_country})
        if records_1:
            for rec in records_1:
                if '_id' in rec:
                    del rec['_id']
                rec['block_date'] = ""
                rec['unblock_date'] = make_date_time()
                n_warning_collection.insert_one(rec)

                threading.Thread(target=__do_the_actual_unblocking, kwargs={'network': rec['source_network']},
                                 daemon=True).start()

            n_blocked_collection.delete_many({"source_geolocation_cc": by_country})

    lock.release()


def warn_all(ips=None, networks=None):
    """
    :param ips :{as format: [{document}, {document}...]}
    :param networks :{as format: [{document}, {document}...]}
    :rtype: object
    """
    if ips is None:
        ips = []
    if networks is None:
        networks = []
    if not ips and not networks:
        return

    lock.acquire()

    blocked_collection = get_blocked_by_ip()
    warning_collection = get_warned_by_ip()
    n_blocked_collection = get_blocked_by_network()
    n_warning_collection = get_warned_by_network()

    if ips:
        for threat in ips:
            ip = threat['source_ip']
            network = threat['source_network']
            if ip:
                if '_id' in threat:
                    del threat['_id']
                b = blocked_collection.find_one({"source_ip": ip, "source_network": network})
                if not b:
                    warning_collection.find_one_and_update({"source_ip": ip, "source_network": network},
                                                           {"$set": threat}, upsert=True)

    if networks:
        for threat in networks:
            ip = threat['source_ip']
            network = threat['source_network']
            if ip:
                if '_id' in threat:
                    del threat['_id']
                b = n_blocked_collection.find_one({"source_ip": ip, "source_network": network})
                if not b:
                    n_warning_collection.find_one_and_update({"source_ip": ip, "source_network": network},
                                                             {"$set": threat}, upsert=True)

    lock.release()


def auto_unblocking():

    lock.acquire()

    unblocking_mins = minutes_before_ip_is_unblocked()
    blocked = get_blocked_by_ip()
    n_blocked = get_blocked_by_network()
    current_date = make_date_time(seconds_to_subtract=(unblocking_mins*60))

    records = blocked.find({"block_date": {"$lte": current_date}})
    data = []
    if records:
        for record in records:
            data.append({record['source_ip'], record['source_network']})

    records_2 = n_blocked.find({"block_date": {"$lte": current_date}})
    if records_2:
        for record in records_2:
            data.append({record['source_ip'], record['source_network']})

    lock.release()

    unblock_all(ips=data)


def auto_unblocking_trigger():
    if not is_auto_unblocking_enabled():
        return False
    auto_unblocking()


def clear_old_records():
    days_for_keeping = int(minutes_to_keep_feed())
    lock.acquire()

    current_date = make_date_time(seconds_to_subtract=days_for_keeping * 60)

    feeds = get_feeds()
    blocked = get_blocked_by_ip()
    n_blocked = get_blocked_by_network()
    warned = get_warned_by_ip()
    n_warned = get_warned_by_network()

    to_delete = feeds.find({"time.observation": {"$lt": current_date}})
    with open(os.path.join(os.getcwd(), "backup.txt"), "a+", encoding="utf-8") as f:
        tmp = []
        for x in to_delete:
            del x['_id']
            tmp.append(x)
        f.write(json.dumps(tmp, ensure_ascii=False))
        f.close()

    blocked.delete_many({"time.observation": {"$lt": current_date}})
    n_blocked.delete_many({"time.observation": {"$lt": current_date}})
    warned.delete_many({"time.observation": {"$lt": current_date}})
    n_warned.delete_many({"time.observation": {"$lt": current_date}})
    feeds.delete_many({"time.observation": {"$lt": parser.parse(current_date).isoformat()}})
    lock.release()


def clear_old_records_trigger():
    if not is_auto_clear_old_records_enabled():
        return False
    clear_old_records()


def get_new_global_alerts():
    """
    alerts from the global space
    :return:
    """
    m = int(minutes_a_record_remains_new())
    new_date = make_date_time(seconds_to_subtract=m * 60)
    f = []
    ip_details = my_ip_details()

    data = get_feeds().find({"time.observation": {"$gt": new_date}, "$or": [
        {"source.ip": {"$exists": True}, "source.network": {"$exists": True}}],
                             "source.network": {"$ne": ip_details['network']}}).sort([("time_observation", DESCENDING)])
    if data and data.count() > 0:
        data = normalize_dict(data)
        for x, value in data.items():
            value['id'] = x
            if '_id' in value:
                del value['_id']

            if 'raw' in value:
                del value['raw']

            f.append(value)

    create_log(None, None, "{0} Global attacks detected : ".format(len(f)), LOG_SYSTEM_TYPE)
    return f


def get_new_local_alerts():
    """
    alerts from own local network
    :return:
    """
    ip_details = my_ip_details()
    m = int(minutes_a_record_remains_new())
    new_date = make_date_time(seconds_to_subtract=m * 60)
    f = []
    if not ip_details:
        return None
    data = get_feeds().find({"time.observation": {"$gt": new_date}, "source.network": ip_details['network'],
                             "$or": [{"source.ip": {"$exists": True}, "source.network": {"$exists": True}}]})\
        .sort([("time_observation", DESCENDING)])
    if data and data.count() > 0:
        data = normalize_dict(data)
        for x, value in data.items():
            value['id'] = x
            if '_id' in value:
                del value['_id']
            if 'raw' in value:
                del value['raw']

            f.append(value)

    create_log(None, None, "{0} Local attacks detected : ".format(len(f)), LOG_SYSTEM_TYPE)
    return f


def __do_the_actual_blocking(ip=None, network=None):
    if not ip and not network:
        return False
    try:
        cmd1 = subprocess.Popen(['echo', SUDO_PASSWORD], stdout=subprocess.PIPE)
        if ip and not ip == '0.0.0.0':
            subprocess.Popen(['sudo', '-S'] + IPTABLES_BLOCK_RULE.format(ip).split(), stdin=cmd1.stdout,
                             stdout=subprocess.PIPE)

        if network and not network == '0.0.0.0/0':
            subprocess.Popen(['sudo', '-S'] + IPTABLES_BLOCK_RULE.format(network).split(), stdin=cmd1.stdout,
                             stdout=subprocess.PIPE)

        subprocess.Popen(['sudo', '-S', 'iptables-save'], stdin=cmd1.stdout, stdout=subprocess.PIPE)

    except subprocess.CalledProcessError as e:
        print(e.output)

    create_log(None, None, "Blocked : " + str(ip or network), LOG_SYSTEM_TYPE)

    return True


def __do_the_actual_unblocking(ip=None, network=None):
    if not ip and not network:
        return False
    try:
        cmd1 = subprocess.Popen(['echo', SUDO_PASSWORD], stdout=subprocess.PIPE)
        if ip and not ip == '0.0.0.0':
            subprocess.Popen(['sudo', '-S'] + IPTABLES_UNBLOCK_RULE.format(ip).split(), stdin=cmd1.stdout,
                             stdout=subprocess.PIPE)

        if network and not network == '0.0.0.0/0':
            subprocess.Popen(['sudo', '-S'] + IPTABLES_UNBLOCK_RULE.format(network).split(), stdin=cmd1.stdout,
                             stdout=subprocess.PIPE)

        subprocess.Popen(['sudo', '-S', 'iptables-save'], stdin=cmd1.stdout, stdout=subprocess.PIPE)

    except subprocess.CalledProcessError as e:
        print(e.output)

    create_log(None, None, "Unblocked : " + str(ip or network), LOG_SYSTEM_TYPE)
    return True


def save_domains(data_list):
    if not data_list or not isinstance(data_list, list):
        return False

    count = redirection_count()
    domain_col = get_domains()
    for doc in data_list:
        if doc['count'] >= count:
            doc['redirected'] = True
            redirect_domain(doc['domain'])
        domain_col.update_one({"_id": doc['_id']}, {"$set": doc}, upsert=True)


def auto_redirection():

    lock.acquire()

    count = redirection_count()
    doms = get_domains()
    records = doms.find({"count": {"$gte": count}})
    lock.release()

    if records and len(records) > 0:
        save_domains(list(records))


def auto_redirection_trigger():
    if not is_auto_redirection_enabled():
        return False
    auto_redirection()


def redirect_domain(domain):
    # to implement real redirection
    address = get_redirection_address()
    pass


def remove_redirected_domain(domain):
    # to implement real redirection
    address = get_redirection_address()
    pass
