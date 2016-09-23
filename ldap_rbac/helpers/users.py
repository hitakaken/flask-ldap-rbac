# -*- coding: utf-8 -*-
from ldap_rbac.models import User
from ldap_rbac.core.helpers import BaseHelper


class UserHelper(BaseHelper):
    """用户集合"""

    def __init__(self, ldap_connection):
        super(UserHelper, self).__init__(ldap_connection)

    def entity_class(self):
        return User

    def lock(self, user):
        pass

    def unlock(self,user):
        pass

    def get_user(self,user, is_roles=False):
        pass

    def get_roles(self,user):
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
