# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod
from bidict import bidict
from ldap.cidict import cidict


class LdapEntity(object):
    """LDAP持久化对象抽象类"""
    __metaclass__ = ABCMeta

    def __init__(self, dn=None, attrs=None, helper=None):
        self.dn = dn
        if attrs is None:
            attrs = {}
        self.object_class = attrs.get('objectClass', self.__class__.object_class)
        if dn is not None and '=' in dn:
            self.idx_field = dn[:dn.index('=')]
            self.idx_value = dn[dn.index('=') + 1:dn.index(',')]
        else:
            self.idx_field = self.__class__.idx_field
        self.attrs = cidict({k if k not in self.mapping.inv else self.mapping.inv[k]: v for k, v in attrs.iteritems()
                             if k.lower() != self.idx_field.lower() and k.lower() != 'objectclass'})

    def is_ldap_attr(self, attr_name):
        return attr_name is not None and (
            attr_name in self.attrs
            or attr_name.lower() in GLOBAL_LDAP_CONFIG.VALID_ATTR_NAMES.get(self.__class__.__name__, [])
        )

    def __getattr__(self, attr_name):
        if attr_name in self.mapping.inv:
            attr_name = self.mapping.inv[attr_name]
        if attr_name.lower() == 'objectclass':
            return self.object_class
        elif attr_name.lower() == self.idx_field.lower():
            return self.idx_value
        elif self.is_ldap_attr(attr_name):
            return self.attrs.get(attr_name, None)
        elif self.is_ldap_attr('ft' + attr_name.title()):
            return self.attrs.get('ft' + attr_name.title(), None)
        else:
            raise AttributeError

    def __setattr__(self, key, value):
        if key in self.mapping.inv:
            key = self.mapping.inv[key]
        if key in self.__dict__ or key in [
            'dn', 'object_class', 'idx_field', 'idx_value', 'attrs', 'cached_attrs']:
            self.__dict__[key] = value
        elif key.lower() == 'objectclass':
            self.object_class = value
        elif key.lower() == self.idx_field.lower():
            self.idx_value = value
        elif self.is_ldap_attr(key):
            self.attrs[key] = value
        elif self.is_ldap_attr('ft' + key.title()):
            self.attrs['ft' + key.title()] = value
        else:
            raise AttributeError

    @classmethod
    def parse(cls, ldap_entry):
        """解析LDAP Entry到对象"""
        (dn, attrs) = ldap_entry
        if not dn:
            return None
        return cls(dn=dn, attrs=attrs)

    def cache_attrs(self):
        self.cached_attrs = self.attrs.copy()

    def update(self, attrs):
        for k, v in attrs.iteritems():
            setattr(self, k, v)
        return self

    def add_modlist(self):
        modlist = [(self.idx_field, self.idx_value), ('objectClass', self.object_class)]
        for k, v in self.attrs.iteritems():
            modlist.append((k, v))
        print modlist
        return modlist

    def modify_modlist(self):
        return modlist.modifyModlist(self.cached_attrs, self.attrs, ignore_attr_types=self.ignore_modify_attr_types)



class BranchEntity(LdapEntity):
    object_class = ['organizationalUnit']
    idx_field = 'ou'

    def __init__(self, dn=None, attrs=None):
        super(BranchEntity, self).__init__(dn=dn, attrs=attrs)

class FortEntity(LdapEntity):
    """Fortress 抽象类"""
    object_class = ['ftMods']
    dn_template = '%s=%s,%s,%s'
    branch_dn_template = '%s,%s'
    branch_class = ['organizationalUnit']
    branch_description = 'Fortress Entity Class'

    def __init__(self, dn=None, attrs=None):
        if attrs is None:
            attrs = {}
        if 'objectClass' not in attrs:
            attrs.update({'objectClass': self.__class__.object_class})
        if dn is None and self.__class__.idx_field in attrs:
            dn = attrs[self.__class__.idx_field]
        if dn is not None and '=' not in dn:
            dn = self.__class__.dn_template % (
                self.__class__.idx_field,
                dn,
                self.__class__.branch_part,
                GLOBAL_LDAP_CONFIG.BASE_DN)
        super(FortEntity, self).__init__(dn=dn, attrs=attrs)





class FortEntityWithProperties(FortEntity):
    """Fortress 含有属性的抽象类"""
    object_class = ['ftProperties', 'ftMods']

    def __init__(self, dn=None, attrs=None):
        super(FortEntityWithProperties, self).__init__(dn=dn, attrs=attrs)

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


class Config(FortEntityWithProperties):
    """Fortress 配置对象"""
    object_class = ['ftProperties', 'device']
    idx_field = 'cn'
    branch_part = 'ou=Config'
    branch_description = 'Fortress Configuration Realms'

    def __init__(self, dn=None, attrs=None):
        super(Config, self).__init__(dn=dn, attrs=attrs)


class Constraint(object):
    __metaclass__ = ABCMeta

    def __init__(self, name, is_temporal_set=True,
                 timeout=None, begin_time=None, end_time=None, begin_date=None, end_date=None,
                 day_mask=None, begin_lock_date=None, end_lock_date=None,
                 **kwargs):
        self.name = name
        self.is_temporal_set = is_temporal_set
        self.timeout = timeout
        self.begin_time = begin_time
        self.end_time = end_time
        self.begin_date = begin_date
        self.end_date = end_date
        self.day_mask = day_mask
        self.begin_lock_date = begin_lock_date
        self.end_lock_date = end_lock_date

    def get_raw_data(self):
        pass


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
