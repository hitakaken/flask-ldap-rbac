# -*- coding: utf-8 -*-
from ldap_rbac.core.models import PropertiesEntity


class User(PropertiesEntity):
    """Fortress People"""
    ID_FIELD = 'uid'
    ROOT = 'ou=People'
    OBJECT_CLASS = ['top', 'inetOrgPerson', 'organizationalPerson',
                    'ftUserAttrs', 'ftProperties', 'ftMods', 'extensibleObject']

    def __init__(self, dn=None, attrs=None):
        super(User, self).__init__(dn=dn, attrs=attrs)
