import pandas as pd


def normalize_dict(data=None):
    if not data:
        return None
    temp_dict = {}
    index = 0
    for feed in data:
        # feed_id = feed['_id']
        feed_id = str(index)
        temp_dict[feed_id] = {}

        for key in feed:
            if isinstance(feed[key], dict):

                for key2 in feed[key]:
                    if isinstance(feed[key][key2], dict):

                        for key3 in feed[key][key2]:
                            if isinstance(feed[key][key2][key3], dict):

                                for key4 in feed[key][key2][key3]:
                                    temp_dict[feed_id][str(key + '_' + key2 + '_' + key3 + '_' + key4)] = \
                                        feed[key][key2][key3][key4]

                            else:
                                temp_dict[feed_id][str(key + '_' + key2 + '_' + key3)] = feed[key][key2][key3]
                    else:
                        temp_dict[feed_id][str(key + '_' + key2)] = feed[key][key2]
            else:
                temp_dict[feed_id][key] = feed[key]
            index += 1

    return temp_dict


def prepare_data_fill_na(data=None):
    if data is None:
        return None
    temp = data.fillna(
        {
            'source_allocated': 0,
            'source_asn': 0,
            'source_as_name': '',
            'source_fqdn': '',
            'source_abuse_contact': '',
            'source_url': '',
            'source_network': '0.0.0.0/0',
            'source_registry': '',
            'source_reverse_dns': '',
            'source_geolocation_cc': 'anonymous',
            'source_ip': '0.0.0.0',
            'classification_type': 'unclassified',
            'classification_taxonomy': 'unknown',
            'feed_accuracy': 0,
            'event_description_text': 'unknown',
        }
    )
    return temp.drop('source_allocated', axis=1)


def convert_series_to_categorical(series=None):
    categorical_frame = None
    if series is not None and not series.empty:
        try:
            """
            categorical_frame = series[['classification_taxonomy', 'classification_type',
                                       'source_ip', 'source_network', 'event_description_text']]\
                .apply(lambda x: x.astype('category'))
            """
            series['time_observation'] = pd.to_datetime(series['time_observation'], format='%Y-%m-%d %H:%M:%S')
            series['time_source'] = pd.to_datetime(series['time_source'], format='%Y-%m-%d %H:%M:%S')
            categorical_frame = series.apply(lambda x: x.astype('category'))

        except Exception:
            raise ValueError("unable to convert series into categorical data")

    return categorical_frame
