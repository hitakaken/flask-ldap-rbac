# -*- coding: utf-8 -*-
from bidict import bidict
from .base import FortEntityWithProperties
from .helper import GLOBAL_LDAP_CONNECTION


class User(FortEntityWithProperties):
    object_class = ['top', 'inetOrgPerson', 'ftUserAttrs', 'ftProperties', 'ftMods', 'extensibleObject']
    idx_field = 'uid'
    branch_part = 'ou=People'
    branch_description = 'Fortress People'
    mapping = bidict(
        mail='emails',
        mobile='mobiles'
    )

    def __init__(self, dn=None, attrs=None):
        super(User, self).__init__(dn=dn, attrs=attrs)


def create(user):
    if isinstance(user, dict):
        user = User(attrs=user)
    if 'sn' not in user.attrs:
        user.attrs['sn'] = user.idx_value
    GLOBAL_LDAP_CONNECTION.add_entry(user)


def read(user):
    if isinstance(user, dict):
        user = User(attrs=user)
    result = GLOBAL_LDAP_CONNECTION.find(user)
    return result


def update(user):
    if isinstance(user, dict):
        user = User(attrs=user)
    cached_user = GLOBAL_LDAP_CONNECTION.find(user)
    result = GLOBAL_LDAP_CONNECTION.save_entry(cached_user.update(user.attrs))
    return result


def delete(user):
    if isinstance(user, dict):
        user = User(attrs=user)


def authenticate(user_id, password):
    user = User(attrs={'uid': 'kcao'})
    print GLOBAL_LDAP_CONNECTION.authenticate(user.dn, password)
