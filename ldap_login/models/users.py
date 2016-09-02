# -*- coding: utf-8 -*-
from .abstract import LDAP_CONNECTION, BASE_DN, FortEntity, get_by_dn


class User(FortEntity):
    object_class = ['top', 'inetOrgPerson', 'ftUserAttrs', 'ftProperties', 'ftMods', 'extensibleObject']

    def __init__(self, dn, attrs):
        if 'objectClass' not in attrs:
            attrs.update({'objectClass': User.object_class})
        if dn.index('=') < 0:
            dn = BASE_DN
        super(User, self).__init__(dn, attrs)


def exists(user):
    return get_by_dn(LDAP_CONNECTION, user.dn, User) is not None



