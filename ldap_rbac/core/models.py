# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod
import constants
from ldap.cidict import cidict
import six
import utils


class LdapEntity(object):
    """LDAP持久化对象抽象类"""
    IGNORE_ATTR_TYPES = []
    ID_FIELD = 'ou'
    ROOT = ''
    OBJECT_CLASS = ['top', 'organizationalUnit']

    def __init__(self, dn=None, attrs=None, helper=None):
        self.__dict__['dn'] = dn
        if attrs is None:
            attrs = cidict()
        if isinstance(attrs, dict):
            attrs = cidict(attrs)
        self.__dict__['attrs'] = attrs
        self.__dict__['cached_attrs'] = None
        self.__dict__['helper'] = helper

    def __getattr__(self, attr_name):
        if attr_name in self.attrs:
            return self.attrs.get(attr_name)
        elif self.helper is not None:
            return self.helper.getattr(self, attr_name)
        else:
            raise AttributeError

    def __setattr__(self, key, value):
        if key in self.attrs:
            self.attrs[key] = value
        elif self.helper is not None:
            self.helper.setattr(self, key, value)
        else:
            raise AttributeError

    def cache(self):
        self.cached_attrs = self.attrs.copy()

    def iid(self):
        if constants.FT_IID not in self.attrs:
            self.attrs[constants.FT_IID] = [utils.uuid()]
        return self.attrs[constants.FT_IID][0]

    def update(self, attrs):
        for k, v in six.iteritems(attrs):
            setattr(self, k, v)
        return self


class PropertiesEntity(LdapEntity):
    """Fortress 含有属性的抽象类"""
    def __init__(self, dn=None, attrs=None, helper=None):
        super(PropertiesEntity, self).__init__(dn=dn, attrs=attrs, helper=helper)
        self.update_props()

    def generate_props(self):
        props = self.attrs.get('ftProps', [])
        if not isinstance(props, list):
            props = [props]
        return utils.unflatten(map(lambda e: tuple(e.split(':', 1)), props))

    def update_props(self):
        self.__dict__['props'] = self.generate_props()

    def __getattr__(self, attr_name):
        if attr_name.lower() == 'properties' or attr_name.lower() == 'props':
            return self.__dict__.get('props', None)
        else:
            return LdapEntity.__getattr__(self, attr_name)

    def __setattr__(self, key, value):
        if key.lower() == 'properties' or key.lower() == 'props':
            self.attrs.update({'ftProps': utils.flatten(value) if value is not None else []})
            self.update_props()
        else:
            LdapEntity.__setattr__(self, key, value)


class Config(PropertiesEntity):
    """Fortress 配置对象
    Fortress Configuration Realms"""
    ID_FIELD = 'cn'
    ROOT = 'ou=Config'
    OBJECT_CLASS = ['ftProperties', 'device']

    def __init__(self, dn=None, attrs=None, helper=None):
        super(Config, self).__init__(dn=dn, attrs=attrs, helper=helper)


class Constraint(object):
    __metaclass__ = ABCMeta

    def __init__(self, name=None,
                 timeout=None, begin_time=None, end_time=None, begin_date=None, end_date=None,
                 day_mask=None, begin_lock_date=None, end_lock_date=None,
                 **kwargs):
        self.name = name
        self.timeout = timeout
        self.begin_time = begin_time
        self.end_time = end_time
        self.begin_date = begin_date
        self.end_date = end_date
        self.day_mask = day_mask
        self.begin_lock_date = begin_lock_date
        self.end_lock_date = end_lock_date

    @abstractmethod
    def raw_data(self):
        return '%s$%s$%s$%s$%s$%s$%s$%s$%s' % (
            self.name,
            utils.xstr(self.timeout),
            utils.xstr(self.begin_time),
            utils.xstr(self.end_time),
            utils.xstr(self.begin_date),
            utils.xstr(self.end_date),
            utils.xstr(self.begin_lock_date),
            utils.xstr(self.end_lock_date),
            utils.xstr(self.day_mask),
        )

    def parse(self, raw_data):
        chunks = raw_data.split('$')
        self.name = chunks[0]
        self.timeout = utils.chunk(chunks, 1, mapping=utils.convert_string_to_integer)
        self.begin_time = utils.chunk(chunks, 2, mapping=utils.convert_string_to_integer)
        self.end_time = utils.chunk(chunks, 3, mapping=utils.convert_string_to_integer)
        self.begin_date = utils.chunk(chunks, 4, mapping=utils.convert_string_to_integer)
        self.end_date = utils.chunk(chunks, 5, mapping=utils.convert_string_to_integer)
        self.begin_lock_date = utils.chunk(chunks, 6, mapping=utils.convert_string_to_integer)
        self.end_lock_date = utils.chunk(chunks, 7, mapping=utils.convert_string_to_integer)
        self.day_mask = utils.chunk(chunks, 8, mapping=utils.convert_string_to_integer)


class Resource(object):
    __metaclass__ = ABCMeta
    permissions = []

    def get_permissions(self):
        return self.permissions

    def add_permission(self, permission):
        self.permissions.append(permission)

    @abstractmethod
    def grant(self, who, permissions):
        pass

    @abstractmethod
    def revoke(self, who, permissions):
        pass

    @abstractmethod
    def revoke_all(self, who):
        pass

    @abstractmethod
    def check(self, who, permission):
        return False

    @abstractmethod
    def check_any(self, who, permissions):
        return False

    @abstractmethod
    def check_all(self, who, permissions):
        return False

    @abstractmethod
    def which(self, who):
        pass

    @abstractmethod
    def show(self):
        pass

    @abstractmethod
    def save(self):
        pass
