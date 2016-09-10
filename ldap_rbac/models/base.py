# -*- coding: utf-8 -*-
import flatdict
from ldap_rbac.models.helper import LdapEntity, GLOBAL_LDAP_CONFIG


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
