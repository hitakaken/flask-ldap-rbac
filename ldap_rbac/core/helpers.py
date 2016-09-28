# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod
import constants
import copy
import ldap
from ldap.cidict import cidict
import ldap.modlist as modlist
import ldap.schema
import schemas
from ldap_rbac.core.models import LdapEntity
import six
import utils


class LdapConfig(object):
    def __init__(self):
        self.BASE_DN = 'dc=novbase,dc=com',
        self.ROOT_DN = 'cn=Manager,dc=novbase,dc=com'
        self.ROOT_PW = 'secret'
        self.LDAP_URL = 'ldap://127.0.0.1'
        self.OBJECT_CLASSES =  copy.deepcopy(schemas.REGISTER_OBJECT_CLASSES)
        self.ENTITY_CLASSES = {}
        self.DESCRIPTION = 'NovBase Software'


class LdapConnection(object):
    def __init__(self, ldap_config=None):
        self.conn = None
        self.auth_conn = None
        self.binding = False
        self.ldap_schema = None
        self.config = LdapConfig()
        self.helpers = {}

        if ldap_config is not None:
            self.init_config(ldap_config)

    def init_config(self, ldap_config):
        if 'OPTIONS' in ldap_config:
            options = ldap_config['OPTIONS']
            if 'DEBUG_LEVEL' in options:
                ldap.set_option(ldap.OPT_DEBUG_LEVEL, options['DEBUG_LEVEL'])
            if options.get('REQUIRE_CERT', False):
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
                if 'CACERTFILE' in options:
                    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, options['CACERTFILE'])
        self.config.LDAP_URL = ldap_config.get('URI', self.config.LDAP_URL)
        self.conn = ldap.initialize(self.config.LDAP_URL, trace_level=ldap_config.get('TRACE_LEVEL', 1))
        self.auth_conn = ldap.initialize(self.config.LDAP_URL)
        self.conn.protocol_version = ldap.VERSION3
        self.auth_conn.protocol_version = ldap.VERSION3
        self.conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
        self.auth_conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
        if ldap_config.get('START_TLS', False):
            self.conn.start_tls_s()
            self.auth_conn.start_tls_s()
        self.config.ROOT_DN = ldap_config['ROOT_DN']
        self.config.ROOT_PW = ldap_config['ROOT_PW']
        self.config.BASE_DN = ldap_config.get('BASE_DN', self.config.BASE_DN)

    def begin(self):
        """开启Admin连接"""
        if not self.binding:
            self.conn.simple_bind_s(self.config.ROOT_DN, self.config.ROOT_PW)
            self.binding = True
        return self

    def end(self):
        # self.conn.unbind_s()
        self.binding = False
        return self

    def initialize(self):
        """初始化"""
        self.begin()
        entity_classes = []
        for name, helper in six.iteritems(self.helpers):
            entity_classes.append(helper.entity_class())
        self.load_entity_classes(entity_classes)
        self.register_entity_classes(entity_classes)

    def load_ldap_schema(self, force=False):
        """加载LDAP Schema"""
        if self.ldap_schema is None or force:
            subschema_subentry_dn, schema = ldap.schema.urlfetch(self.config.LDAP_URL)
            self.ldap_schema = schema

    def load_ldap_object_classes(self, schema_names, force=False):
        """加载LDAP Schema Object Class"""
        if self.ldap_schema is None or force:
            self.load_ldap_schema(force=force)
        for schema_name in schema_names:
            if schema_name not in self.config.OBJECT_CLASSES or force:
                schema_attr_obj = self.ldap_schema.get_obj(ldap.schema.ObjectClass, schema_name)
                if schema_attr_obj is not None:
                    self.config.OBJECT_CLASSES[schema_name] = {}
                    if len(schema_attr_obj.must) > 0:
                        self.config.OBJECT_CLASSES[schema_name]['MUST'] = list(schema_attr_obj.must)
                    if len(schema_attr_obj.may) > 0:
                        self.config.OBJECT_CLASSES[schema_name]['MAY'] = list(schema_attr_obj.may)

    def root_dn(self, entity_class):
        """实体对象根节点DN"""
        return '%s,%s' % (entity_class.ROOT, self.config.BASE_DN) if len(entity_class.ROOT) > 0 \
            else self.config.BASE_DN

    def root_entry(self, entity_class):
        """实体对象根节点"""
        dn = self.root_dn(entity_class)
        k, v = dn[:dn.index(',')].split('=')
        attrs = {
            'objectClass': ['organizationalUnit'],
            k: [v]
        }
        if entity_class.__doc__ is not None and len(entity_class.__doc__) > 0:
            attrs['description'] = entity_class.__doc__
        return dn, attrs

    def create(self, dn, attrs):
        """创建条目"""
        self.begin()
        self.conn.add_s(dn, attrs.items())

    def find_one(self, dn):
        """根据DN获取条目"""
        self.begin()
        try:
            result = self.conn.search_s(dn, ldap.SCOPE_BASE)
        except ldap.NO_SUCH_OBJECT:
            return None
        if result is not None and len(result) > 0:
            dn, attrs = result[0]
            return dn, cidict(dict(attrs))
        else:
            return None

    def find_all(self, base_dn, filters, limit=0, skip=0):
        """查询条目"""
        result_id = self.conn.search(base_dn, ldap.SCOPE_SUBTREE, filters)
        count = 0
        while True:
            count += 1
            if limit != 0 and count >= limit:
                break
            try:
                result_type, result_data = self.conn.result(result_id, 0)
            except ldap.NO_SUCH_OBJECT:
                break
            if count <= skip:
                continue
            if result_type == ldap.RES_SEARCH_ENTRY:
                dn = result_data[0][0]
                attrs = cidict(dict(result_data[0][1]))
                yield dn, attrs
            else:
                break

    def count(self, base_dn, filters):
        # TODO
        return 0

    def exists(self, dn):
        """判断条目是否存在"""
        return self.find_one(dn) is not None

    def update(self, dn, new_attrs, old_attrs, ignore_attr_types=None):
        """更新条目"""
        self.begin()
        if ignore_attr_types is None:
            ignore_attr_types = []
        self.conn.modify_s(
            dn,
            modlist.modifyModlist(old_attrs, new_attrs, ignore_attr_types=ignore_attr_types))

    def save(self, dn, attrs, ignore_attr_types=None):
        """保存条目"""
        result = self.find_one(dn)
        if result is None:
            self.create(dn, attrs)
        else:
            dn, old_attrs = result
            self.update(dn, attrs, old_attrs, ignore_attr_types=ignore_attr_types)

    def load_entity_classes(self, entity_classes):
        """加载对象实体类"""
        self.begin()
        missing = []
        for entity_class in entity_classes:
            for object_class in entity_class.OBJECT_CLASS:
                if object_class not in self.config.OBJECT_CLASSES and object_class not in missing:
                    missing.append(object_class)
        if len(missing) > 0:
            self.load_ldap_object_classes(missing)
        for entity_class in entity_classes:
            class_name = entity_class.__name__
            self.config.ENTITY_CLASSES[class_name] = {
                'ROOT': self.root_dn(entity_class),
                'OBJECT_CLASS': entity_class.OBJECT_CLASS
            }
            must = []
            may = []
            for object_class in entity_class.OBJECT_CLASS:
                if object_class in self.config.OBJECT_CLASSES:
                    if 'MUST' in self.config.OBJECT_CLASSES[object_class]:
                        must += self.config.OBJECT_CLASSES[object_class]['MUST']
                    if 'MAY' in self.config.OBJECT_CLASSES[object_class]:
                        may += self.config.OBJECT_CLASSES[object_class]['MAY']
            must = list(set(must))
            may = list(set(may)-set(must))
            self.config.ENTITY_CLASSES[class_name]['MUST'] = must
            self.config.ENTITY_CLASSES[class_name]['MAY'] = may
            self.config.ENTITY_CLASSES[class_name]['ALL'] = must + may

    def entry_must_attributes(self, entry):
        """对象的必须属性"""
        class_name = entry.__class__.__name__
        if class_name not in self.config.ENTITY_CLASSES:
            self.load_entity_classes([entry.__class__])
        return self.config.ENTITY_CLASSES[class_name]['MUST']

    def entry_may_attributes(self, entry):
        """对象的可能属性"""
        class_name = entry.__class__.__name__
        if class_name not in self.config.ENTITY_CLASSES:
            self.load_entity_classes([entry.__class__])
        return self.config.ENTITY_CLASSES[class_name]['MAY']

    def register_entity_classes(self, entity_classes):
        """注册实体对象类"""
        self.load_entity_classes(entity_classes)
        for entity_class in entity_classes:
            if not self.exists(self.root_dn(entity_class)):
                dn, attrs = self.root_entry(entity_class)
                self.create(dn, attrs)


class BaseHelper(object):
    """对象集合接口"""
    __metaclass__ = ABCMeta

    def __init__(self, ldap_connection, name=None):
        self.ldap = ldap_connection
        self.name = name if name is not None else self.__class__.__name__
        self.register()

    @abstractmethod
    def entity_class(self):
        return LdapEntity

    def get_dn(self, entry, entity_class=None):
        entity_class = self.entity_class() if entity_class is None else entity_class
        if entry.dn is not None and '=' not in entry.dn:
            entry.dn = '%s=%s,%s' % (entity_class.ID_FIELD, entry.dn, self.ldap.root_dn(entity_class))
        if entry.dn is None and entity_class.ID_FIELD in entry.attrs:
            entry.dn = self.id_to_dn(entry.attrs[entity_class.ID_FIELD])
        return entry.dn

    def id_to_dn(self, entry_id, entity_class=None):
        entity_class = self.entity_class() if entity_class is None else entity_class
        return '%s=%s,%s' % (entity_class.ID_FIELD, entry_id, self.ldap.root_dn(entity_class))

    def instance(self, dn=None, attrs=None, **kwargs):
        cls = self.entity_class()
        entry = cls(dn=dn, attrs=attrs, helper=self, **kwargs)
        self.get_dn(entry)
        if 'objectClass' not in entry.attrs:
            entry.attrs['objectClass'] = self.entity_class().OBJECT_CLASS
        if cls.ID_FIELD not in entry.attrs:
            entry.attrs[cls.ID_FIELD] = utils.rdn(entry.dn)
        return entry

    def getattr(self, entry, attr_name):
        if attr_name == 'name':
            return entry.attrs.get(entry.ID_FIELD, None)
        class_name = self.entity_class().__name__
        if attr_name in self.ldap.config.ENTITY_CLASSES[class_name]['ALL']:
            return entry.attrs[attr_name]
        ft_attr_name = constants.FT_PREFIX + attr_name.title()
        if ft_attr_name in self.ldap.config.ENTITY_CLASSES[class_name]['ALL']:
            return entry.attrs[ft_attr_name]
        else:
            raise AttributeError

    def setattr(self, entry, key, value):
        if key == 'name':
            entry.attrs[entry.ID_FIELD] = value
            return
        class_name = self.entity_class().__name__
        if key in self.ldap.config.ENTITY_CLASSES[class_name]['ALL']:
            entry.attrs[key] = value
            return
        ft_key = constants.FT_PREFIX + key.title()
        if ft_key in self.ldap.config.ENTITY_CLASSES[class_name]['ALL']:
            entry.attrs[ft_key] = value
        else:
            entry.__dict__[key] = value

    def create(self, entry):
        if isinstance(entry, dict):
            entry = self.instance(attrs=dict)
        dn = self.get_dn(entry)
        class_name = self.entity_class().__name__
        if constants.FT_IID in self.ldap.config.ENTITY_CLASSES[class_name]['MUST']:
            entry.iid()
        entry.fill()
        self.ldap.create(dn, entry.attrs)
        entry.cache()
        return entry

    def find_one(self, entry_id):
        dn = self.id_to_dn(entry_id) if '=' not in entry_id else entry_id
        result = self.ldap.find_one(dn)
        if result is not None:
            dn, attrs = result
            result = self.instance(dn=dn, attrs=attrs)
            result.cache()
        return result

    def exists(self, entry_id):
        """判断条目是否存在"""
        return self.find_one(entry_id) is not None

    def find_all(self, conditions, limit=0, skip=0):
        if conditions is None:
            filters = constants.FILTER_TRUE
        else:
            if isinstance(conditions, dict):
                conditions = conditions.items()
            filters = []
            for k, v in conditions:
                filters.append('(%s=%s)' % (k, v))
            if len(filters) == 0:
                filters = constants.FILTER_TRUE
            elif len(filters) == 1:
                filters = filters[0]
            else:
                filters = '(&%s)' % (''.join(filters))
        results = []
        for dn, attrs in self.ldap.find_all(
                self.ldap.root_dn(self.entity_class()), filters=filters, limit=limit, skip=skip):
            result = self.instance(dn=dn, attrs=attrs)
            result.cache()
            results.append(result)
        return results

    def count(self, conditions):
        # TODO
        return 0

    def update(self, entry):
        if isinstance(entry, dict):
            entry = self.instance(attrs=dict)
        dn = self.get_dn(entry)
        self.ldap.update(dn, entry.attrs, entry.cached_attrs, ignore_attr_types=self.entity_class().IGNORE_ATTR_TYPES)
        entry.cache()
        return entry

    def save(self, entry):
        if isinstance(entry, dict):
            entry = self.instance(attrs=dict)
        if entry.cached_attrs is None:
            origin_entry = self.find_one(entry.attrs.get(self.entity_class().ID_FIELD))
            if origin_entry is None:
                return self.create(entry)
            else:
                origin_entry.update(attrs=entry.attrs)
                return self.update(origin_entry)
        else:
            return self.update(entry)


    def delete(self, entry_id):
        # TODO
        pass

    def register(self):
        self.ldap.helpers[self.name] = self
