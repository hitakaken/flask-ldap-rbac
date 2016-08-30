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
    from flask.ext.login import current_user
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
        self.conn = None
        self._config = None
        self._raise_errors = False

        self.acl = AccessControlList()
        self.before_acl = {'allow': [], 'deny': []}

        self._role_model = kwargs.get('role_model', RoleMixin)
        self._user_model = kwargs.get('user_model', UserMixin)
        self._user_loader = kwargs.get('user_loader', lambda: current_user)

        if app is not None:
            self.app = app
        if app is not None or len(kwargs) > 0:
            self.init_app(app, **kwargs)

    def init_app(self, app, **kwargs):
        self._config = app.config.get('LDAP', {})

        self.config.setdefault('BIND_DN', '')
        self.config.setdefault('BIND_AUTH', '')
        self.config.setdefault('URI', 'ldap://127.0.0.1')

        from ldap_login.controllers import mod_ldap_login as ldap_login_module
        setattr(ldap_login_module, 'ldap_manager', self)
        app.register_blueprint(ldap_login_module, **kwargs)
        app.before_first_request(self._setup_acl)
        app.before_request(self._authenticate)

    @property
    def config(self):
        """LDAP配置参数"""
        return self._config

    def set_raise_errors(self, state=True):
        '''
        Set the _raise_errors flags to allow for the calling code to provide error handling.
        This is especially helpful for debugging from flask_ldap_login_check.
        '''
        self._raise_errors = state

    def connect(self):
        """初始化LDAP连接，"""
        log.debug("Connecting to ldap server %s" % self.config['URI'])
        self.conn = ldap.initialize(self.config['URI'])

        for opt, value in self.config.get('OPTIONS', {}).items():
            if isinstance(opt, str):
                opt = getattr(ldap, opt)

            try:
                if isinstance(value, str):
                    value = getattr(ldap, value)
            except AttributeError:
                pass
            self.conn.set_option(opt, value)

        if self.config.get('START_TLS'):
            log.debug("Starting TLS")
            self.conn.start_tls_s()

    def initialize_ldap_modules(self):
        self.connect()

        log.debug("Performing bind/search")
        ctx = {'username': username, 'password': password}
        user = self.config['BIND_DN'] % ctx

        bind_auth = self.config['BIND_AUTH']
        try:
            log.debug("Binding with the BIND_DN %s" % user)
            self.conn.simple_bind_s(user, bind_auth)

        except ldap.INVALID_CREDENTIALS:
            msg = "Could not connect bind with the BIND_DN=%s" % user
            log.debug(msg)
            if self._raise_errors:
                raise ldap.INVALID_CREDENTIALS(msg)
            return None

    def bind_search(self, username, password):
        """
        Bind to BIND_DN/BIND_AUTH then search for user to perform lookup.
        """

        log.debug("Performing bind/search")

        ctx = {'username': username, 'password': password}

        user = self.config['BIND_DN'] % ctx

        bind_auth = self.config['BIND_AUTH']
        try:
            log.debug("Binding with the BIND_DN %s" % user)
            self.conn.simple_bind_s(user, bind_auth)
        except ldap.INVALID_CREDENTIALS:
            msg = "Could not connect bind with the BIND_DN=%s" % user
            log.debug(msg)
            if self._raise_errors:
                raise ldap.INVALID_CREDENTIALS(msg)
            return None

        user_search = self.config.get('USER_SEARCH')

        results = None
        found_user = False
        for search in user_search:
            base = search['base']
            filt = search['filter'] % ctx
            scope = search.get('scope', ldap.SCOPE_SUBTREE)
            log.debug("Search for base=%s filter=%s" % (base, filt))
            results = self.conn.search_s(base, scope, filt, attrlist=self.attrlist)
            if results:
                found_user = True
                log.debug("User with DN=%s found" % results[0][0])
                try:
                    self.conn.simple_bind_s(results[0][0], password)
                except ldap.INVALID_CREDENTIALS:
                    self.conn.simple_bind_s(user, bind_auth)
                    log.debug("Username/password mismatch, continue search...")
                    results = None
                    continue
                else:
                    log.debug("Username/password OK")
                    break
        if not results and self._raise_errors:
            msg = "No users found matching search criteria: {}".format(user_search)
            if found_user:
                msg = "Username/password mismatch"
            raise ldap.INVALID_CREDENTIALS(msg)

        log.debug("Unbind")
        self.conn.unbind_s()

        return self.format_results(results)

    def direct_bind(self, username, password):
        """
        Bind to username/password directly
        """
        log.debug("Performing direct bind")

        ctx = {'username': username, 'password': password}
        scope = self.config.get('SCOPE', ldap.SCOPE_SUBTREE)
        user = self.config['BIND_DN'] % ctx

        try:
            log.debug("Binding with the BIND_DN %s" % user)
            self.conn.simple_bind_s(user, password)
        except ldap.INVALID_CREDENTIALS:
            if self._raise_errors:
                raise ldap.INVALID_CREDENTIALS("Unable to do a direct bind with BIND_DN %s" % user)
            return None
        results = self.conn.search_s(user, scope, attrlist=self.attrlist)
        self.conn.unbind_s()
        return self.format_results(results)

    def ldap_login(self, username, password):
        """
        Authenticate a user using ldap. This will return a userdata dict
        if successfull.
        ldap_login will return None if the user does not exist or if the credentials are invalid
        """
        self.connect()

        if self.config.get('USER_SEARCH'):
            result = self.bind_search(username, password)
        else:
            result = self.direct_bind(username, password)
        return result

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

