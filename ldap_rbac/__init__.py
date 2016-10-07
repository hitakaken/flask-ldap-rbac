# -*- coding: utf-8 -*-
import logging

from flask import Blueprint, _request_ctx_stack
from flask_login import LoginManager
from ldap_rbac.extensions import api
from ldap_rbac.core import exceptions
from ldap_rbac.helpers import LdapConnection, ConfigHelper, UserHelper, RoleHelper, TokenHelper

try:
    from flask import _app_ctx_stack
except ImportError:
    _app_ctx_stack = None

connection_stack = _app_ctx_stack or _request_ctx_stack

log = logging.getLogger(__name__)

try:
    from flask_login import current_user
except ImportError:
    current_user = None


class RBACManager(object):
    def __init__(self, app=None, **kwargs):
        self.api = None
        self.configs = None
        self.users = None
        self.roles = None
        self.tokens = None
        self.login_manager = None

        if app is not None:
            self.app = app
            self.init_app(app, **kwargs)

    def init_app(self, app, **kwargs):
        # LDAP 定义
        connection = LdapConnection(ldap_config=app.config['LDAP'])
        connection.begin()
        # DAO 定义
        self.configs = ConfigHelper(connection, name='configs')
        self.users = UserHelper(connection, name='users')
        self.roles = RoleHelper(connection, name='roles')
        # 初始化
        connection.initialize()
        # 令牌池
        self.tokens = TokenHelper(jwt_config=app.config.get('JWT', {}), token_config=app.config.get('TOKEN'))
        self.login_manager = LoginManager()
        self.login_manager.request_loader(self.tokens.load_user_from_request)
        # 注册异常
        api.add_namespace(exceptions.api)
        api.authorizations = {'apiKey': {
            'type': 'apiKey', 'in': 'header', 'name': self.tokens.token_header}
        }
        # 注册模型
        # api.add_namespace(context.namespace)
        # 注册管理模块
        from ldap_rbac.manager.access import api as access_manager
        for module in [access_manager,
                       # admin_manager, group_manager, review_manager
                       ]:
            api.add_namespace(module)
        if 'apis' in kwargs:
            for ns in kwargs['apis']:
                api.add_namespace(ns)
        # 生成蓝图
        api_blueprint = Blueprint('api', __name__)
        api.init_app(api_blueprint)
        app.register_blueprint(api_blueprint, **kwargs)
        self.api = api
        setattr(app, 'rbac', self)
        setattr(app, 'login_manager', self.login_manager)
