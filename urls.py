# -*- coding: utf-8 -*-
from api.analysis_query import blocked_or_warned, get_plot_data, block_ip, unblock_ip, unblock_by_country, \
    block_by_country, block_network, unblock_network, get_local_notifications, get_global_notifications, \
    update_settings, fetch_settings, fetch_domains, redirect_domain_handle, remove_redirected_domain_handle
from api.authenticate import index, login, logout
from api.logs import fetch_logs, delete_logs
from api.users import add_user, deactivate_user, fetch_all_users, fetch_single_user, confirm_email, change_password, \
    update_user, forgot_password, confirm_password_reset, activate_user


def generate_urls(app):
    app.add_url_rule('/', view_func=index, methods=['GET'])
    app.add_url_rule('/api/', view_func=index, methods=['GET'], strict_slashes=False)
    app.add_url_rule('/api/authenticate/', view_func=index, methods=['GET'], strict_slashes=False)
    app.add_url_rule('/api/authenticate/login/', view_func=login, methods=['POST'], strict_slashes=False)
    app.add_url_rule('/api/authenticate/logout/<user_id>/<token>/', view_func=logout, methods=['GET'],
                     strict_slashes=False)
    app.add_url_rule('/api/logs/fetch/<user_id>/<log_type>/<token>/', view_func=fetch_logs, methods=['GET'],
                     strict_slashes=False)
    app.add_url_rule('/api/logs/delete/<user_id>/<retain>/<log_type>/<token>/', view_func=delete_logs,
                     methods=['DELETE'],
                     strict_slashes=False)
    app.add_url_rule('/api/user/add/', view_func=add_user, methods=['POST'], strict_slashes=False)
    app.add_url_rule('/api/user/confirm/<token>/', view_func=confirm_email, methods=['GET'], strict_slashes=False)
    app.add_url_rule('/api/user/deactivate/<string:email>/<user_id>/<token>/', view_func=deactivate_user,
                     methods=['DELETE'], strict_slashes=False)
    app.add_url_rule('/api/user/activate/', view_func=activate_user, methods=['POST'], strict_slashes=False)
    app.add_url_rule('/api/user/fetch/all/<user_id>/<token>/', view_func=fetch_all_users, methods=['GET'],
                     strict_slashes=False)
    app.add_url_rule('/api/user/fetch/one/<user_email_id>/<user_id>/<token>', view_func=fetch_single_user,
                     methods=['GET'],
                     strict_slashes=False)
    app.add_url_rule('/api/user/password/change/', view_func=change_password, methods=['POST'], strict_slashes=False)
    app.add_url_rule('/api/user/password/forgot/<email>/', view_func=forgot_password, methods=['GET'],
                     strict_slashes=False)
    app.add_url_rule('/api/user/password/reset/', view_func=confirm_password_reset, methods=['POST'],
                     strict_slashes=False)
    app.add_url_rule('/api/user/update/', view_func=update_user, methods=['PUT'], strict_slashes=False)
    app.add_url_rule('/api/analysis/fetch/<category>/<order>/<user_id>/<token>/', view_func=blocked_or_warned,
                     methods=['GET'],
                     strict_slashes=False)
    app.add_url_rule('/api/analysis/fetch/plots/<user_id>/<token>/', view_func=get_plot_data, methods=['GET'],
                     strict_slashes=False)
    app.add_url_rule('/api/analysis/block/ip/', view_func=block_ip, methods=['POST'], strict_slashes=False)
    app.add_url_rule('/api/analysis/unblock/ip/', view_func=unblock_ip, methods=['POST'], strict_slashes=False)
    app.add_url_rule('/api/analysis/unblock/country/<country>/<user_id>/<token>/', view_func=unblock_by_country,
                     methods=['GET'],
                     strict_slashes=False)
    app.add_url_rule('/api/analysis/block/country/<country>/<user_id>/token/', view_func=block_by_country,
                     methods=['GET'],
                     strict_slashes=False)
    app.add_url_rule('/api/analysis/block/network/', view_func=block_network, methods=['POST'], strict_slashes=False)
    app.add_url_rule('/api/analysis/unblock/network/', view_func=unblock_network, methods=['POST'],
                     strict_slashes=False)
    app.add_url_rule('/api/analysis/notifications/fetch/local/<user_id>/<token>/', view_func=get_local_notifications,
                     methods=['GET'], strict_slashes=False)
    app.add_url_rule('/api/analysis/notifications/fetch/global/<user_id>/<token>/', view_func=get_global_notifications,
                     methods=['GET'], strict_slashes=False)
    app.add_url_rule('/api/settings/update/', view_func=update_settings, methods=['POST'], strict_slashes=False)
    app.add_url_rule('/api/settings/fetch/<user_id>/<token>/', view_func=fetch_settings, methods=['GET'],
                     strict_slashes=False)
    app.add_url_rule('/api/domains/fetch/<user_id>/<token>/', view_func=fetch_domains, methods=['GET'],
                     strict_slashes=False)
    app.add_url_rule('/api/domains/redirect/', view_func=redirect_domain_handle, methods=['POST'], strict_slashes=False)
    app.add_url_rule('/api/domains/redirect/remove/', view_func=remove_redirected_domain_handle, methods=['POST'],
                     strict_slashes=False)
