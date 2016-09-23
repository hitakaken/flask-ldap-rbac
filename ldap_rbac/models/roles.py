# -*- coding: utf-8 -*-
from ldap_rbac.core.models import FortEntityWithProperties, Constraint


class Role(FortEntityWithProperties):
    object_class = ['top', 'ftRls', 'ftProperties', 'ftMods']
    idx_field = 'cn'
    branch_part = 'ou=Roles,ou=RBAC'
    branch_description = 'Fortress Roles'

    def __init__(self, dn=None, attrs=None):
        super(Role, self).__init__(dn=dn, attrs=attrs)


class UserRole(Constraint):
    def __init__(self, user, role, **kwargs):
        super(UserRole, self).__init__(role, **kwargs)


def create(role):
    if isinstance(role, dict):
        role = Role(attrs=role)
    GLOBAL_LDAP_CONNECTION.add_entry(role)


def read(role):
    if isinstance(role, dict):
        role = Role(attrs=role)
    role = GLOBAL_LDAP_CONNECTION.find(role)
    return role


def update(role):
    if isinstance(role, dict):
        role = Role(attrs=role)
    cached_user = GLOBAL_LDAP_CONNECTION.find(role)
    result = GLOBAL_LDAP_CONNECTION.save_entry(cached_user.update(role.attrs))
    return result


def delete_parent(role):
    if isinstance(role, dict):
        role = Role(attrs=role)


def remove(role):
    if isinstance(role, dict):
        role = Role(attrs=role)


def assign(role, user_dn):
    pass


def deassign(role, user_dn):
    pass


def get_role(role):
    pass


def find_roles(role, limit=0):
    pass


def find_assigned_roles(user_dn):
    pass


