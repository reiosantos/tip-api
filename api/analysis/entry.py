import threading

import pandas as pd

from api.analysis.config import default_settings, ip_max_attempts_to_block, minutes_before_ip_is_blocked, \
    ip_max_attempts_to_warn
from api.analysis.database import get_feeds, get_settings, save_settings
from api.analysis.normalize_data import normalize_dict, prepare_data_fill_na, convert_series_to_categorical
from api.analysis.post_actions_handler import clear_old_records_trigger, auto_unblocking_trigger
from api.analysis.pre_actions_handler import filter_for_blocking, generate_plots, filter_dns

lock = threading.Lock()


def main_function():
    # pandas options for terminal development. Not needed in production mode
    pd.set_option('display.width', None)
    pd.set_option('display.max_colwidth', 500)
    pd.set_option('display.show_dimensions', True)

    with lock:
        if not get_settings().count() > 0:
            save_settings(default_settings)

        feeds_collection = get_feeds()

        m_data = feeds_collection.find()

        if m_data.count() > 0:
            normal_data_dictionary = normalize_dict(m_data)
            if len(normal_data_dictionary) > 0:
                data_frame = pd.DataFrame.from_dict(normal_data_dictionary, orient='index').drop(
                    ['raw', '_id', 'feed_url', 'feed_name', 'feed_provider', 'event_description_url', 'extra'], axis=1)

                prepared = prepare_data_fill_na(data_frame)

                categorical_data_frame = convert_series_to_categorical(prepared)

                generate_plots(categorical_data_frame)

                threading.Thread(filter_for_blocking(categorical_data_frame, ip_max_attempts_to_block(),
                                                     minutes_before_ip_is_blocked(), "block")).start()
                threading.Thread(filter_for_blocking(categorical_data_frame, ip_max_attempts_to_warn(),
                                                     minutes_before_ip_is_blocked(), "warn")).start()
                threading.Thread(filter_dns(categorical_data_frame)).start()

            else:
                print("No data found. Set is empty")
        else:
            print("Data query is empty. No records found")

        # auto_unblocking_trigger()
        # clear_old_records_trigger()
        # auto_redirection_trigger()

# analysis_thread = threading.Thread(target=main_function, args=(), name="analysis_thread", daemon=True)


class RepeatingTimer(threading.Timer):
    def run(self):
        """
        while not self.finished.wait(self.interval):
            self.function(*self.args, **self.kwargs)
            # self.finished.wait(self.interval)
        """
        while not self.finished.is_set():
            self.function(*self.args, **self.kwargs)
            self.finished.wait(self.interval)
