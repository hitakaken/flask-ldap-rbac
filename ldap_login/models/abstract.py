# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod
import ldap
from ldap.cidict import cidict

LDAP_CONNECTION = None
BASE_DN = 'dc=novbase,dc=com'

valid_attr_names = {
    'LdapEntity': [],
    'FortEntity': [ 'ftModifier', 'ftModCode', 'ftModId']
}

must_attr_names = {
    'LdapEntity': [],
    'FortEntity': []
}

may_attr_names = {
    'LdapEntity': [],
    'FortEntity': ['ftModifier', 'ftModCode', 'ftModId']
}


class LdapEntity(object):
    """LDAP持久化对象抽象类"""
    __metaclass__ = ABCMeta

    def __init__(self, dn, attrs):
        self.dn = dn
        self.object_class = attrs.get('objectClass', [])
        self.idx_field = dn[:dn.index('=')]
        self.idx_value = dn[dn.index('=') + 1:dn.index(',')]
        if attrs is None:
            attrs = {}
        self.attrs = cidict({k: v for k, v in attrs.iteritems()
                             if k.lower() != self.idx_field.lower() and k.lower() != 'objectclass'})

    def is_ldap_attr(self, attr_name):
        global valid_attr_names
        return attr_name is not None and (
            attr_name in self.attrs or attr_name in valid_attr_names.get(self.__class__.__name__, {})
        )

    def __getattr__(self, attr_name):
        if attr_name.lower() == 'objectclass':
            return self.object_class
        elif attr_name.lower() == self.idx_field.lower:
            return self.idx_value
        elif self.is_ldap_attr(attr_name):
            return self.attrs.get(attr_name, None)
        else:
            raise AttributeError

    @classmethod
    def parse(cls, ldap_entry):
        """解析LDAP Entry到对象"""
        (dn, attrs) = ldap_entry
        if not dn:
            return None
        return cls(dn, attrs)


def get_by_dn(ldap_connection, dn, entity_class):
    try:
        ldap_entity = ldap_connection.search_s(dn, ldap.SCOPE_BASE, '(objectClass=*)')
        if entity_class is None:
            entity_class = LdapEntity
        return entity_class.parse(ldap_entity)
    except ldap.NO_SUCH_OBJECT:
        return None


def search(ldap_connection,  base_dn, filters, entity_class):
    try:
        results = ldap_connection.search_s(base_dn, ldap.SCOPE_SUBTREE, filters)
        if results is None:
            return []
        if entity_class is None:
            entity_class = LdapEntity
        result_set = []
        for dn, entry in results:
            result_set.append(entity_class.parse((dn, entry)))
    except ldap.NO_SUCH_OBJECT:
        return []


def add_entry(ldap_connection, entry):
    modlist = [(entry.idx_field, entry.idx_value), ('objectClass', entry.object_class)]
    for k, v in entry.attrs.iteritems():
        modlist.append((k, v))
    ldap_connection.add_s(entry.dn, modlist)


def save_entry(ldap_connection, entry):
    modlist = [(entry.idx_field, entry.idx_value), ('objectClass', entry.object_class)]
    for k, v in entry.attrs.iteritems():
        modlist.append((k, v))
    ldap_connection.mod(entry.dn, modlist)


class FortEntity(LdapEntity):
    """Fortress 抽象类"""
    object_class = ['ftMods']

    def __init__(self, dn, attrs):
        if 'objectClass' not in attrs:
            attrs.update({'objectClass': FortEntity.object_class})
        super(FortEntity, self).__init__(dn, attrs)
