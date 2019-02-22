from api.database import get_mongodb_connection
from config.settings import MONGO_FEEDS_COLLECTION, \
    MONGO_BLOCKED_IP_COLLECTION, MONGO_BLOCKED_NETWORK_COLLECTION, MONGO_WARNING_NETWORK_COLLECTION, \
    MONGO_WARNING_IP_COLLECTION, MONGO_SETTINGS_COLLECTION, MONGO_PLOTS_COLLECTION, MONGO_DOMAINS_COLLECTION


def get_feeds():
    return get_mongodb_connection(MONGO_FEEDS_COLLECTION)


def get_blocked_by_ip():
    return get_mongodb_connection(MONGO_BLOCKED_IP_COLLECTION)


def get_blocked_by_network():
    return get_mongodb_connection(MONGO_BLOCKED_NETWORK_COLLECTION)


def get_warned_by_ip():
    return get_mongodb_connection(MONGO_WARNING_IP_COLLECTION)


def get_warned_by_network():
    return get_mongodb_connection(MONGO_WARNING_NETWORK_COLLECTION)


def save_settings(settings):
    if not settings or not isinstance(settings, dict):
        return False

    settings_col = get_mongodb_connection(MONGO_SETTINGS_COLLECTION)
    for key, val in settings.items():
        settings_col.update_one({"_id": key}, {"$set": {key: val}}, upsert=True)
    return True


def get_settings(key=None):
    settings_col = get_mongodb_connection(MONGO_SETTINGS_COLLECTION)
    if not key:
        return settings_col.find()

    doc = settings_col.find_one({"_id": key})
    if doc and key in doc:
        return doc[key]
    return False


def get_plots():
    return get_mongodb_connection(MONGO_PLOTS_COLLECTION)


def save_plots(plots_dict):
    if not plots_dict or not isinstance(plots_dict, dict):
        return False

    plots_col = get_plots()
    for key, val in plots_dict.items():
        plots_col.update_one({"_id": str(key)}, {"$set": {str(key): val}}, upsert=True)


def get_domains():
    return get_mongodb_connection(MONGO_DOMAINS_COLLECTION)



