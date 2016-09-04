# -*- coding: utf-8 -*-
from .base import LDAP_CONNECTION, BASE_DN, FortEntityWithProperties, get_by_dn


class User(FortEntityWithProperties):
    object_class = ['top', 'inetOrgPerson', 'ftUserAttrs', 'ftProperties', 'ftMods', 'extensibleObject']
    idx_field = 'cn'
    branch_part = 'ou=People'
    branch_class = 'organizationalUnit'
    branch_description = 'Fortress People'

    def __init__(self, dn, attrs=None):
        if attrs is None:
            attrs = {}
        if 'objectClass' not in attrs:
            attrs.update({'objectClass': User.object_class})
        if dn is None and User.idx_field in attrs:
            dn = attrs[User.idx_field]
        if dn.index('=') < 0:
            dn = '%s=%s,%s,%s' % (User.idx_field, dn, User.branch_part, BASE_DN)
        super(User, self).__init__(dn, attrs)


def exists(user):
    return get_by_dn(LDAP_CONNECTION, user.dn, User) is not None


