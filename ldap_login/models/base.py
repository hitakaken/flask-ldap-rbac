# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod
import flatdict
import ldap
from ldap.cidict import cidict
import datetime as dt
from bson.objectid import ObjectId
from uuid import UUID

LDAP_CONNECTION = None
BASE_DN = 'dc=novbase,dc=com'

VALID_ATTR_NAMES = {
    'LdapEntity': [],
    'FortEntity': ['ftModifier', 'ftModCode', 'ftModId']
}

MUST_ATTR_NAMES = {
    'LdapEntity': [],
    'FortEntity': []
}

MAY_ATTR_NAMES = {
    'LdapEntity': [],
    'FortEntity': ['ftModifier', 'ftModCode', 'ftModId']
}


class LdapEntity(object):
    """LDAP持久化对象抽象类"""
    __metaclass__ = ABCMeta

    def __init__(self, dn, attrs=None):
        self.dn = dn
        self.object_class = attrs.get('objectClass', [])
        self.idx_field = dn[:dn.index('=')]
        self.idx_value = dn[dn.index('=') + 1:dn.index(',')]
        if attrs is None:
            attrs = {}
        self.attrs = cidict({k: v for k, v in attrs.iteritems()
                             if k.lower() != self.idx_field.lower() and k.lower() != 'objectclass'})

    def is_ldap_attr(self, attr_name):
        global VALID_ATTR_NAMES
        return attr_name is not None and (
            attr_name in self.attrs or attr_name in VALID_ATTR_NAMES.get(self.__class__.__name__, {})
        )

    def __getattr__(self, attr_name):
        if attr_name.lower() == 'objectclass':
            return self.object_class
        elif attr_name.lower() == self.idx_field.lower():
            return self.idx_value
        elif self.is_ldap_attr(attr_name):
            return self.attrs.get(attr_name, None)
        else:
            raise AttributeError

    def __setattr__(self, key, value):
        if key.lower() == 'objectclass':
            self.object_class = value
        elif key.lower() == self.idx_field.lower():
            self.idx_value = value
        elif self.is_ldap_attr(key):
            self.attrs[key] = value
        else:
            raise AttributeError

    @classmethod
    def parse(cls, ldap_entry):
        """解析LDAP Entry到对象"""
        (dn, attrs) = ldap_entry
        if not dn:
            return None
        return cls(dn, attrs=attrs)


def get_by_dn(ldap_connection, dn, entity_class):
    try:
        ldap_entity = ldap_connection.search_s(dn, ldap.SCOPE_BASE, '(objectClass=*)')
        if entity_class is None:
            entity_class = LdapEntity
        return entity_class.parse(ldap_entity)
    except ldap.NO_SUCH_OBJECT:
        return None


def search(ldap_connection, base_dn, entity_class, filters=None):
    try:
        if filters is None:
            filters = 'objectClass=*'
        results = ldap_connection.search_s(base_dn, ldap.SCOPE_SUBTREE, '(%s)' % filters)
        if results is None:
            return []
        if entity_class is None:
            entity_class = LdapEntity
        result_set = []
        for dn, entry in results:
            result_set.append(entity_class.parse((dn, entry)))
    except ldap.NO_SUCH_OBJECT:
        return []


class UTC(dt.tzinfo):
    ZERO = dt.timedelta(0)

    def utcoffset(self, dt):
        return self.ZERO

    def tzname(self, dt):
        return 'UTC'

    def dst(self, dt):
        return self.ZERO

UTC = UTC()
UUID_1_EPOCH = dt.datetime(1582, 10, 15, tzinfo=UTC)
UUID_TICKS_PER_SECOND = 10000000


def unix_time_to_uuid_time(dt):
    return int((dt - UUID_1_EPOCH).total_seconds() * UUID_TICKS_PER_SECOND)


def object_id_to_uuid(object_id):
    """
    Converts ObjectId to UUID

    :param object_id: some ObjectId
    :return: UUID
    """
    str_object_id = str(object_id)

    b = []
    for i in [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22]:
        b.append(int(str_object_id[i:i+2], 16))

    generation_time = ObjectId(str_object_id).generation_time.astimezone(UTC)
    time = unix_time_to_uuid_time(generation_time)
    time |= (b[4] >> 6) & 0x3

    most_sig_bits = str(hex(0x1000 | time >> 48 & 0x0FFF
                            | time >> 16 & 0xFFFF0000
                            | time << 32))[9:]

    least_sig_bits = str(hex(2 << 62
                             | (b[4] & 0x3F) << 56 | (b[5] & 0xFF) << 48
                             | (b[6] & 0xFF) << 40 | (b[7] & 0xFF) << 32
                             | (b[8] & 0xFF) << 24 | (b[9] & 0xFF) << 16
                             | (b[10] & 0xFF) << 8 | b[11] & 0xFF))[2:]

    return UUID('%s-%s-%s-%s-%s' % (most_sig_bits[:8], most_sig_bits[8:12], most_sig_bits[12:16],
                               least_sig_bits[0:4], least_sig_bits[4:]))


def add_entry(ldap_connection, entry):
    if entry.is_ldap_attr('ftId') and 'ftId' not in entry.attrs:
        entry.attrs['ftId'] = str(object_id_to_uuid(ObjectId()))
    must_attr_names = MUST_ATTR_NAMES.get(entry.__class__.__name__, [])
    for must_attr_name in must_attr_names:
        if must_attr_name not in entry.attrs:
            raise ldap.OBJECT_CLASS_VIOLATION('Missing Attribute: %s' % must_attr_name)
    modlist = [(entry.idx_field, entry.idx_value), ('objectClass', entry.object_class)]
    for k, v in entry.attrs.iteritems():
        modlist.append((k, v))
    ldap_connection.add_s(entry.dn, modlist)


def save_entry(ldap_connection, entry):
    modlist = [(entry.idx_field, entry.idx_value), ('objectClass', entry.object_class)]
    for k, v in entry.attrs.iteritems():
        modlist.append((k, v))
    ldap_connection.mod(entry.dn, modlist)


class BranchEntity(LdapEntity):
    object_class = ['organizationalUnit']
    idx_field = 'ou'

    def __init__(self, dn, attrs=None):
        if attrs is None:
            attrs = {}
        if 'objectClass' not in attrs:
            attrs.update({'objectClass': BranchEntity.object_class})
        if dn is None and BranchEntity.idx_field in attrs:
            dn = attrs[BranchEntity.idx_field]
        if dn.index('=') < 0:
            dn = '%s=%s,%s' % (BranchEntity.idx_field, dn, BASE_DN)
        super(BranchEntity, self).__init__(dn, attrs=attrs)


class FortEntity(LdapEntity):
    """Fortress 抽象类"""
    object_class = ['ftMods']

    def __init__(self, dn, attrs=None):
        if attrs is None:
            attrs = {}
        if 'objectClass' not in attrs:
            attrs.update({'objectClass': FortEntity.object_class})
        super(FortEntity, self).__init__(dn, attrs=attrs)


def flatten(properties):
    flat = flatdict.FlatDict(properties, delimiter='.')
    result = []
    for k, v in flat.iteritems():
        result.append('%s:%s' % (k, v))
    return result


def unflatten(flatten_properties, splitter=None ):
    dict_out = {}
    splitter = '.' if splitter is None else splitter
    for key, value in flatten_properties:
        keys = key.split(splitter)
        temp_dict = dict_out
        for i in range(len(keys)-1):
            if isinstance(temp_dict, list):
                idx = int(keys[i])
                for ii in range(len(dict_out), idx+1):
                    temp_dict.append(None)
                if temp_dict[idx] is None:
                    temp_dict[idx] = [] if keys[i+1].isdigit() else {}
                temp_dict = temp_dict[idx]
            elif isinstance(temp_dict, dict):
                field = keys[i]
                if field not in temp_dict:
                    temp_dict[field] = [] if keys[i+1].isdigit() else {}
                temp_dict = temp_dict[field]
        if isinstance(temp_dict, list):
            idx = int(keys[-1])
            for ii in range(len(temp_dict), idx + 1):
                temp_dict.append(None)
            temp_dict[idx] = value
        elif isinstance(temp_dict, dict):
            field = keys[-1]
            temp_dict[field] = value
    return dict_out


class FortEntityWithProperties(FortEntity):
    """Fortress 含有属性的抽象类"""
    object_class = ['ftProperties', 'ftMods']

    def __init__(self, dn, attrs):
        if attrs is None:
            attrs = {}
        if 'objectClass' not in attrs:
            attrs.update({'objectClass': FortEntityWithProperties.object_class})
        super(FortEntityWithProperties, self).__init__(dn, attrs=attrs)

    def __getattr__(self, attr_name):
        if attr_name.lower() == 'properties' or attr_name.lower() == 'props':
            props = self.attrs.get('ftProps', [])
            if not isinstance(props, list):
                props = [props]
            return unflatten(map(lambda e: tuple(e.split(':', 1)), props))
        else:
            return FortEntity.__getattr__(self, attr_name)

    def __setattr__(self, key, value):
        if key.lower() == 'properties' or key.lower() == 'props':
            self.attrs.update({'ftProps': flatten(value) if value is not None else None})
        else:
            FortEntity.__setattr__(self, key, value)




