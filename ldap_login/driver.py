# -*- coding: utf-8 -*-
import ldap
import logging

log = logging.getLogger(__name__)


def scalar(value):
    """
    Take return a value[0] if `value` is a list of length 1
    """
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return value[0]
    return value


def _is_utf8(s):
    try:
        if isinstance(s, str):
            us = s.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


class LdapDriver(object):
    def __init__(self, config=None):
        self.conn = None
        self._raise_errors = False
        self._config = config if config is not None else {}
        self.config.setdefault('BIND_DN', '')
        self.config.setdefault('BIND_AUTH', '')
        self.config.setdefault('URI', 'ldap://127.0.0.1')

    def format_results(self, results):
        """
        将查询结果规范化
        """
        if not results:
            return None
        userdn = results[0][0]
        userobj = results[0][1]
        userobj['dn'] = userdn

        keymap = self.config.get('KEY_MAP')
        if keymap:
            return {key: scalar(userobj.get(value)) for key, value in keymap.items() if
                    _is_utf8(scalar(userobj.get(value)))}
        else:
            return {key: scalar(value) for key, value in userobj.items() if _is_utf8(scalar(value))}

    @property
    def config(self):
        """LDAP配置参数"""
        return self._config

    @property
    def attrlist(self):
        """Transform the KEY_MAP paramiter into an attrlist for ldap filters"""
        keymap = self.config.get('KEY_MAP')
        if keymap:
            # https://github.com/ContinuumIO/flask-ldap-login/issues/11
            # https://continuumsupport.zendesk.com/agent/tickets/393
            return [s.encode('utf-8') for s in keymap.values()]
        else:
            return None

    def set_raise_errors(self, state=True):
        """
        Set the _raise_errors flags to allow for the calling code to provide error handling.
        This is especially helpful for debugging from flask_ldap_login_check.
        """
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

    def initialize_rbac_models(self):
        self.connect()

        log.debug("Initialize RBAC Models ")
        bind_dn = self.config['BIND_DN']
        bind_auth = self.config['BIND_AUTH']
        try:
            log.debug("Binding with the BIND_DN %s" % bind_dn)
            self.conn.simple_bind_s(bind_dn, bind_auth)

        except ldap.INVALID_CREDENTIALS:
            msg = "Could not connect bind with the BIND_DN=%s"
            log.debug(msg)
            if self._raise_errors:
                raise ldap.INVALID_CREDENTIALS(msg)
            return None
