# -*- coding: utf-8 -*-
import itertools
import ldap
import logging

from flask import request, abort, _request_ctx_stack

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


class LDAPLoginManager(object):
    def __init__(self, app=None, **kwargs):

        self.acl = AccessControlList()
        self.before_acl = {'allow': [], 'deny': []}

        # self._role_model = kwargs.get('role_model', RoleMixin)
        # self._user_model = kwargs.get('user_model', UserMixin)
        # self._user_loader = kwargs.get('user_loader', lambda: current_user)

        if app is not None:
            self.app = app
        if app is not None or len(kwargs) > 0:
            self.init_app(app, **kwargs)

    def init_app(self, app, **kwargs):
        from ldap_login.manager.access import access_manager
        from ldap_login.manager.admin import admin_manager
        from ldap_login.manager.group import group_manager
        from ldap_login.manager.review import review_manager
        for module in [access_manager, admin_manager, group_manager, review_manager]:
            app.register_blueprint(module, **kwargs)
        app.before_first_request(self._setup_acl)
        app.before_request(self._authenticate)

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

