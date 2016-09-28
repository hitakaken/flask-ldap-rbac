# -*- coding: utf-8 -*-
from ldap_rbac.core import constants
from flask_login import UserMixin


class TokenUser(UserMixin):
    def __init__(self, name=None, uid=None, alias=None,
                 roles=None, admin_roles=None, group=None, groups=None,
                 helper=None):
        self.name = name
        self.id = uid
        self.alias = [] if alias is None else alias
        self.roles = [] if roles is None else roles
        self.admin_roles = [] if admin_roles is None else admin_roles
        self.group = group
        self.groups = [] if groups is None else groups
        self.helper = helper

    def has_role(self, role_name):
        return role_name in self.roles

    @property
    def is_admin(self):
        return self.has_role(constants.ROLE_NAME_ADMIN)
