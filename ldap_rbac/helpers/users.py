# -*- coding: utf-8 -*-
from ldap_rbac.core import constants, utils
from ldap_rbac.models import User, PWPolicy
from ldap_rbac.core.helpers import BaseHelper


class UserHelper(BaseHelper):
    """用户集合"""

    def __init__(self, ldap_connection, name=None):
        super(UserHelper, self).__init__(ldap_connection, name=name)

    def entity_class(self):
        return User

    def getattr(self, user, attr_name):
        if attr_name == 'locked':
            return constants.OPENLDAP_PW_LOCKED_TIME in user.attrs \
                   and user.attrs[constants.OPENLDAP_PW_LOCKED_TIME][0] == constants.LOCK_VALUE
        elif attr_name == 'system_user':
            return constants.SYSTEM_USER in user.attrs \
                   and user.attrs[constants.SYSTEM_USER][0] == 'true'
        elif attr_name == 'pwpolicy':
            return None if constants.OPENLDAP_POLICY_SUBENTRY not in user.attrs \
                else utils.rdn(user.attrs[constants.OPENLDAP_POLICY_SUBENTRY][0])
        else:
            return super(UserHelper, self).getattr(user, attr_name)

    def setattr(self, user, key, value):
        if key == 'locked':
            if value is True:
                user.attrs[constants.OPENLDAP_PW_LOCKED_TIME] = [constants.LOCK_VALUE]
            else:
                user.attrs.pop(constants.OPENLDAP_PW_LOCKED_TIME, None)
        elif key == 'system_user':
            if value is True:
                user.attrs[constants.SYSTEM_USER] = ['true']
            else:
                user.attrs.pop(constants.SYSTEM_USER, None)
        elif key == 'pwpolicy':
            if value is None:
                user.attrs.pop(constants.OPENLDAP_POLICY_SUBENTRY, None)
            else:
                user.attrs[constants.OPENLDAP_POLICY_SUBENTRY] = [value.cn if isinstance(value, PWPolicy) else value]
        else:
            super(UserHelper, self).setattr(user, key, value)

    def lock(self, user):
        user.locked = True
        self.save(user)

    def unlock(self, user):
        user.locked = False
        self.save(user)

    def get_user(self, user, is_roles=False):
        pass

    def get_roles(self, user):
        pass

    def get_role_names(self, user):
        pass

    def get_admin_roles(self,user):
        pass

    def check_passwd(self, user, password):
        try:
            GLOBAL_LDAP_CONNECTION.auth_conn.simple_bind_s(user.dn, password)
            return True
        except ldap.INVALID_CREDENTIALS:
            return False

    def check_pw_policies(self, user):
        pass

    def get_authorized_users(self,role, limit=0):
        pass

    def get_assigned_users(self,role, limit=0):
        pass

    def change_password(self,user, oldpw, newpw, check=True):
        user = read(user)
        if check and 'userpassword' in user.attrs:
            if oldpw is None or not check_passwd(user, oldpw):
                raise exceptions.InvalidCredentials()
        if not check or 'userpassword' not in user.attrs:
            oldpw = None
        GLOBAL_LDAP_CONNECTION.conn.passwd_s(user.dn, oldpw, newpw)

    def assign(self, user_role):
        pass

    def deassign(self, user_role):
        pass

    def get_user_roles(self, uid):
        pass

    def authenticate(self, user, password):
        user = read(user)
        if user is None:
            raise exceptions.UserNotFound()
        if not check_passwd(user, password):
            raise exceptions.InvalidCredentials()
        return user
