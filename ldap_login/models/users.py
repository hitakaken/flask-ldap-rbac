# -*- coding: utf-8 -*-
from .base import FortEntityWithProperties
from .helper import GLOBAL_LDAP_CONNECTION


class User(FortEntityWithProperties):
    object_class = ['top', 'inetOrgPerson', 'ftUserAttrs', 'ftProperties', 'ftMods', 'extensibleObject']
    idx_field = 'uid'
    branch_part = 'ou=People'
    branch_description = 'Fortress People'

    def __init__(self, dn=None, attrs=None):
        super(User, self).__init__(dn=dn, attrs=attrs)


def find(user):
    if isinstance(user, dict):
        user = User(attrs=user)
    result = GLOBAL_LDAP_CONNECTION.find(user)
    return result




def add_user(user):
    if isinstance(user, dict):
        user = User(attrs=user)
    if 'sn' not in user.attrs:
        user.attrs['sn'] = user.idx_value
    GLOBAL_LDAP_CONNECTION.add_entry(user)
