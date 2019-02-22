from collections import Counter
from datetime import datetime

from dateutil import relativedelta
from pandas._libs.tslib import Timestamp

from api.analysis.config import CLASSIFICATION_TABLE, ATTACK_BY_TYPE, ATTACK_BY_NETWORK, ATTACK_BY_IP, ATTACK_BY_ASN, \
    ATTACK_BY_DATES, ATTACK_BY_LOCATION, ATTACK_PER_DAY_HOUR, ATTACK_BY_TYPE_AGAINST_DATES_SERIES
from api.analysis.database import save_plots
from api.analysis.post_actions_handler import block_all, warn_all, save_domains
from api.database import create_log
from config.settings import LOG_SYSTEM_TYPE


def generate_plots(da=None):
    if da is None:
        return None

    def modify_date(x):
        if "T" in x:
            return datetime.strptime(x.split(".")[0], "%Y-%m-%dT%H:%M:%S")
        return datetime.strptime(x.split(".")[0], "%Y-%m-%d %H:%M:%S")

    groups = da.groupby(['classification_type', 'classification_taxonomy']).groups
    bar = {}
    # name_types = {}
    for attack_result in groups:
        name, taxonomy = attack_result
        bar[str(name)] = groups[attack_result].size
        # name_types[name] = taxonomy

    description_groups = da.groupby(['classification_type', 'event_description_text']).groups
    class_type_description = {}
    for description_result in description_groups:
        event_type, name = description_result
        if not name:
            name = "unknown"
        if not event_type:
            event_type = "unclassified"

        name_count = description_groups[description_result].size

        if event_type not in class_type_description:
            class_type_description[str(event_type)] = []

        ct = {"name": name, "count": name_count}
        class_type_description[str(event_type)].append(ct)

    network_groups = da.groupby(['source_network']).groups
    network_counts = {}
    for network_result in network_groups:
        network_counts[str(network_result)] = network_groups[network_result].size

    ip_groups = da.groupby(['source_ip']).groups
    ip_counts = {}
    for ip_result in ip_groups:
        ip_counts[str(ip_result)] = ip_groups[ip_result].size

    asn_groups = da.groupby(['source_asn']).groups
    asn_counts = {}
    for asn_result in asn_groups:
        asn_counts[str(asn_result)] = asn_groups[asn_result].size

    geo_groups = da.groupby(['source_geolocation_cc']).groups
    geo_counts = {}
    for geo_result in geo_groups:
        geo_counts[str(geo_result)] = geo_groups[geo_result].size

    type_series = da.groupby(['classification_type'])
    series = {}
    for group, data in type_series:
        temp = {}
        items = dict(Counter(list(data.time_observation.values)))
        for key, val in items.items():
            if isinstance(key, Timestamp):
                key = str(key)
            temp[key] = val
        series[str(group)] = temp

    hourly = da.groupby(da.time_source.map(lambda t: t.hour)).groups
    hourly_plots = []
    for hour in hourly:
        tmp = {"hour": hour, "counts": len(hourly[hour])}
        hourly_plots.append(tmp)

    da['time_observation'] = da.time_observation.astype(str).apply(lambda x: modify_date(x))
    da['time_source'] = da.time_observation.astype(str).apply(lambda x: modify_date(x))
    da['time_observation'] = da.time_observation.astype(datetime)
    da['time_source'] = da.time_source.astype(datetime)

    today = datetime.now().date()
    yesterday = today - relativedelta.relativedelta(days=1)
    this_week = today.isocalendar()[1]
    last_month = today - relativedelta.relativedelta(months=1)

    dt = da[da['time_observation'].dt.date == today]
    dy = da[da['time_observation'].dt.date == yesterday]
    dtw = da[(da['time_observation'].dt.week == this_week) &
             (da['time_observation'].dt.year == today.year)]
    dtm = da[(da['time_observation'].dt.month == today.month) &
             (da['time_observation'].dt.year == today.year)]
    dtlm = da[(da['time_observation'].dt.month == last_month.month) &
              (da['time_observation'].dt.year == last_month.year)]

    by_dates = {
        "attacks_today": len(dt),
        "attacks_yesterday": len(dy),
        "attacks_this_week": len(dtw),
        "attacks_this_month": len(dtm),
        "attacks_last_month": len(dtlm),
    }

    plots = {
        CLASSIFICATION_TABLE: class_type_description,
        ATTACK_BY_TYPE: bar,
        ATTACK_BY_IP: ip_counts,
        ATTACK_BY_NETWORK: network_counts,
        ATTACK_BY_ASN: asn_counts,
        ATTACK_BY_LOCATION: geo_counts,
        ATTACK_BY_DATES: by_dates,
        ATTACK_BY_TYPE_AGAINST_DATES_SERIES: series,
        ATTACK_PER_DAY_HOUR: hourly_plots,
    }
    save_plots(plots)

    create_log(None, None, "system generated plots", LOG_SYSTEM_TYPE)


def __get_condition(frame, action, ip_count):
    """
    if action == "block":
        return len(frame) >= t_hold
    else:
        return not len(frame) >= t_hold
    """
    return len(frame) >= ip_count


def __calculate_row_date_diff(group, action, ip_block_count, blocking_line, ip_type):
    times_btn_attacks = []

    x = group.sort_values(by=['time_source'], ascending=False)
    x.reset_index(inplace=True, drop=True)
    if not x.empty:

        for ind, row in x.iterrows():
            current = x.iloc[ind]
            next_row = x.iloc[ind]
            if (ind + 1) < len(x):
                next_row = x.iloc[ind+1]

            diff = (current['time_source'] - next_row['time_source'])
            days = diff.days if (diff.days >= 0) else -diff.days
            seconds = diff.seconds if (diff.seconds >= 0) else -diff.seconds
            difference = (days * 24 * 60) + (seconds/60)
            times_btn_attacks.append(difference)

        count = 0
        x['attempts'] = 0
        x['overall_attempts'] = len(x)
        if len(times_btn_attacks) >= 0:
            if ip_block_count < 1:
                ip_block_count = 1

            for mins in times_btn_attacks[:ip_block_count]:
                x['attempts'] += 1
                # d = True if 0 <= (mins - blocking_line) < 30 else False
                if 0 <= mins <= blocking_line:  # or d:
                    count += 1
                else:
                    if count > 0:
                        count -= 1

            def calculate_confidence(ro1):
                return int(ro1['attempts'])/ip_block_count * 100

            x['confidence_level'] = x.apply(calculate_confidence, axis=1)

            if action == "block":
                if count >= ip_block_count:
                    if ip_type == "ip_valid":
                        return x.drop_duplicates('source_ip', keep='first')
                    elif ip_type == "ip_invalid":
                        return x.drop_duplicates('source_network', keep='first')
            else:
                if ip_type == "ip_valid":
                    return x.drop_duplicates('source_ip', keep='first')
                elif ip_type == "ip_invalid":
                    return x.drop_duplicates('source_network', keep='first')


def to_dict(df):
    data = []
    keys = df.keys()
    for row in df.itertuples(index=False):
        d = {}
        for key in keys:
            obj = getattr(row, key)
            if isinstance(obj, Timestamp):
                obj = str(obj)
            d[key] = obj
        data.append(d)
    return data


def filter_for_blocking(df, ip_block_warn, blocking_line, action_type):
    with_valid_ips = df[df['source_ip'] != '0.0.0.0']
    with_invalid_ips = df[df['source_ip'] == '0.0.0.0']

    filtered_valid_ips = with_valid_ips.groupby(['source_ip'], as_index=False)\
        .filter(lambda x: __get_condition(x, action_type, ip_block_warn))
    filtered_invalid_ips = with_invalid_ips.groupby(['source_network'], as_index=False)\
        .filter(lambda x: __get_condition(x, action_type, ip_block_warn))

    if not filtered_valid_ips.empty:
        grouped_valid_ips = filtered_valid_ips.groupby(['source_ip'], as_index=False)
        valid = grouped_valid_ips.apply(__calculate_row_date_diff, action_type, ip_block_warn, blocking_line, "ip_valid")

        if not valid.empty:
            # data_dict =valid.to_dict(orient='records')
            data_dict = to_dict(valid)
            if action_type == "block":
                block_all(ips=data_dict)
            else:
                warn_all(ips=data_dict)

    if not filtered_invalid_ips.empty:
        grouped_invalid_ips = filtered_invalid_ips.groupby(['source_network'], as_index=False)
        invalid = grouped_invalid_ips.apply(__calculate_row_date_diff, action_type, ip_block_warn, blocking_line,
                                            "ip_invalid")

        if not invalid.empty:
            # data_dict = invalid.to_dict(orient='records')
            data_dict = to_dict(invalid)
            if action_type == "block":
                block_all(networks=data_dict)
            else:
                warn_all(networks=data_dict)


def filter_dns(df=None):
    if df is None or df.empty:
        return df

    groups = df.groupby(['source_fqdn'], as_index=False).groups
    domains_data = []
    for group in groups:
        if group and not group == "":
            temp = {"_id": group, "domain": group, "count": groups[group].size, "redirected": False}
            domains_data.append(temp)

    save_domains(domains_data)

