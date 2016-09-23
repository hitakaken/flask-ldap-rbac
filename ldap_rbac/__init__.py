# -*- coding: utf-8 -*-
import logging

from flask import Blueprint, request, abort, _request_ctx_stack
from flask_login import LoginManager
import exceptions
from ldap_rbac.extensions import api
# from ldap_rbac.models import context, users

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


class AccessControlList(object):
    def __init__(self):
        self._allowed = []
        self._denied = []
        self._exempt = []
        self.seted = False


class RBACManager(object):
    def __init__(self, app=None, **kwargs):
        self.api = None
        self.acl = AccessControlList()
        self.before_acl = {'allow': [], 'deny': []}
        self.login_manager = LoginManager()
        self.login_manager.request_loader(self.load_user_from_request)
        # self._role_model = kwargs.get('role_model', RoleMixin)
        # self._user_model = kwargs.get('user_model', UserMixin)
        # self._user_loader = kwargs.get('user_loader', lambda: current_user)

        if app is not None:
            self.app = app
            self.init_app(app, **kwargs)


    def init_app(self, app, **kwargs):
        # 初始化LDAP
        # context.initialize_ldap(app.config['LDAP'])
        # 初始化JWT
        # context.initialize_jwt(app.config.get('JWT', {}))
        # 注册异常
        api.add_namespace(exceptions.api)
        # 注册模型
        # api.add_namespace(context.namespace)
        # 注册管理模块
        from ldap_rbac.manager import access_manager, admin_manager, group_manager, review_manager
        for module in [access_manager,
                       # admin_manager, group_manager, review_manager
                       ]:
            api.add_namespace(module)
        # 生成蓝图
        api_blueprint = Blueprint('api', __name__)
        api.init_app(api_blueprint)
        app.register_blueprint(api_blueprint, **kwargs)
        app.before_first_request(self._setup_acl)
        app.before_request(self._authenticate)
        self.api = api
        setattr(app, 'rbac', self)

    def get_app(self, reference_app=None):
        """Helper method that implements the logic to look up an application.
        """
        if reference_app is not None:
            return reference_app
        if self.app is not None:
            return self.app
        ctx = connection_stack.top
        if ctx is not None:
            return ctx.app
        raise RuntimeError('application not registered on rbac '
                           'instance and no application bound '
                           'to current context')

    def _authenticate(self):
        app = self.get_app()

    def _setup_acl(self):
        for rn, method, resource, with_children in self.before_acl['allow']:
            role = self._role_model.get_by_name(rn)
            if rn == 'anonymous':
                role = rn
            else:
                role = self._role_model.get_by_name(rn)
            self.acl.allow(role, method, resource, with_children)
        for rn, method, resource, with_children in self.before_acl['deny']:
            role = self._role_model.get_by_name(rn)
            self.acl.deny(role, method, resource, with_children)
        self.acl.seted = True

    def load_user_from_request(self, request):
        user = None

        # if hasattr(request, 'oauth'):
        #    user = request.oauth.user
        # else:
        #     is_valid, oauth = oauth2.verify_request(scopes=[])
        #    if is_valid:
        #         user = oauth.user
        return user
