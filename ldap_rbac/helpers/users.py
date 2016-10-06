# -*- coding: utf-8 -*-
import ldap
from ldap_rbac.core import constants, utils, exceptions
from ldap_rbac.core.helpers import BaseHelper
from ldap_rbac.models import User, UserRole, PWPolicy


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
        elif attr_name == 'roles':
            return self.get_role_names(user=user)
        elif attr_name == 'is_admin':
            return constants.ROLE_NAME_ADMIN in self.get_role_names(user=user)
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

    def load(self, user):
        results = self.find_all({'sn': user})
        if len(results) == 1:
            return results[0]
        elif len(results) == 0:
            raise exceptions.USER_NOT_FOUND
        else:
            raise exceptions.USER_SEARCH_FAILED

    def lock(self, user):
        user.locked = True
        self.save(user)

    def unlock(self, user):
        user.locked = False
        self.save(user)

    def get_user(self, user, is_roles=False):
        pass

    def get_roles(self, user):
        return [] if constants.USER_ROLE_ASSIGN not in user.attrs else map(
            lambda raw_data: UserRole(user=user, raw_data=raw_data),
            user.attrs[constants.USER_ROLE_DATA]
        )

    def get_role_names(self, user):
        return [] if constants.USER_ROLE_ASSIGN not in user.attrs else user.attrs[constants.USER_ROLE_ASSIGN]

    def get_admin_roles(self,user):
        pass

    def check_password(self, user, password):
        try:
            self.ldap.auth_conn.simple_bind_s(user.dn, password)
            return True
        except ldap.INVALID_CREDENTIALS:
            return False

    def check_pw_policies(self, user):
        pass

    def get_authorized_users(self, role, limit=0):
        pass

    def get_assigned_users(self, role, limit=0):
        pass

    def change_password(self, user, oldpw, newpw, check=True):
        user = self.load(user)
        if check and 'userpassword' in user.attrs:
            if oldpw is None or not self.check_password(user, oldpw):
                raise exceptions.USER_PW_INVLD
        if not check or 'userpassword' not in user.attrs:
            oldpw = None
        self.ldap.conn.passwd_s(user.dn, oldpw, newpw)

    def assign(self, user_role):
        if constants.USER_ROLE_ASSIGN not in user_role.user.attrs:
            user_role.user.attrs[constants.USER_ROLE_ASSIGN] = []
        user_role.user.attrs[constants.USER_ROLE_ASSIGN].append(user_role.name)
        if constants.USER_ROLE_DATA not in user_role.user.attrs:
            user_role.user.attrs[constants.USER_ROLE_DATA] = []
        user_role.user.attrs[constants.USER_ROLE_DATA].append(user_role.raw_data())
        return self

    def deassign(self, user_role):
        user_roles = self.get_roles(user_role.user)
        if len(user_roles) > 0:
            idx = -1
            for i, role in enumerate(user_roles):
                if role.name == user_role.name:
                    idx = i
                    break
            if idx > 0:
                user_role.user.attrs[constants.USER_ROLE_ASSIGN].pop(idx)
                user_role.user.attrs[constants.USER_ROLE_DATA].pop(idx)

    def get_user_roles(self, uid):
        pass

    def authenticate(self, username, password):
        user = self.load(username)
        if user is None:
            raise exceptions.USER_NOT_FOUND
        if not self.check_password(user, password):
            raise exceptions.USER_PW_INVLD
        return user
