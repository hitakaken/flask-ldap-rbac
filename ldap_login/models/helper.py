# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod
from bson.objectid import ObjectId
import datetime as dt
from bidict import bidict
from ldap.cidict import cidict
import ldap
import ldap.schema
import ldap.modlist as modlist
import operator
from uuid import UUID


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
    uuid_string = '%s-%s-%s-%s-%s' % (most_sig_bits[:8], most_sig_bits[8:12], most_sig_bits[12:16],
                                      least_sig_bits[0:4], least_sig_bits[4:-1])
    return UUID(uuid_string)


class LdapConfig(object):
    def __init__(self):
        self.BASE_DN = 'dc=novbase,dc=com',
        self.VALID_ATTR_NAMES = {
            'LdapEntity': [],
            'FortEntity': ['ftModifier', 'ftModCode', 'ftModId']
        }
        self.MUST_ATTR_NAMES = {
            'LdapEntity': [],
            'FortEntity': []
        }
        self.MAY_ATTR_NAMES = {
            'LdapEntity': [],
            'FortEntity': ['ftModifier', 'ftModCode', 'ftModId']
        }
        self.LDAP_URL = 'ldap://127.0.0.1'
        self.OBJECT_CLASSES = {}
        self.DESCRIPTION = 'NovBase Software'


GLOBAL_LDAP_CONFIG = LdapConfig()


class LdapEntity(object):
    """LDAP持久化对象抽象类"""
    __metaclass__ = ABCMeta
    idx_field = 'cn'
    idx_value = None
    attrs = {}
    cached_attrs = {}
    object_class = []
    id_attr_names = ['ftId']
    ignore_modify_attr_types = ['userPassword']
    mapping = bidict()

    def __init__(self, dn=None, attrs=None):
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
        return modlist

    def modify_modlist(self):
        return modlist.modifyModlist(self.cached_attrs, self.attrs, ignore_attr_types=self.ignore_modify_attr_types)


class BranchEntity(LdapEntity):
    object_class = ['organizationalUnit']
    idx_field = 'ou'

    def __init__(self, dn=None, attrs=None):
        super(BranchEntity, self).__init__(dn=dn, attrs=attrs)


class LdapConnection(object):
    def __init__(self, ldap_config=None):
        self.conn = None
        self.auth_conn = None
        self.root_dn = None
        self.root_pw = None
        self.binding = False

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
        GLOBAL_LDAP_CONFIG.LDAP_URL = ldap_config.get('URI', GLOBAL_LDAP_CONFIG.LDAP_URL)
        self.conn = ldap.initialize(GLOBAL_LDAP_CONFIG.LDAP_URL, trace_level=ldap_config.get('TRACE_LEVEL', 1))
        self.auth_conn = ldap.initialize(GLOBAL_LDAP_CONFIG.LDAP_URL)
        self.conn.protocol_version = ldap.VERSION3
        self.auth_conn.protocol_version = ldap.VERSION3
        self.conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
        self.auth_conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
        if ldap_config.get('START_TLS', False):
            self.conn.start_tls_s()
            self.auth_conn.start_tls_s()
        self.root_dn = ldap_config['ROOT_DN']
        self.root_pw = ldap_config['ROOT_PW']
        GLOBAL_LDAP_CONFIG.BASE_DN = ldap_config.get('BASE_DN', GLOBAL_LDAP_CONFIG.BASE_DN)

    def begin(self):
        self.conn.simple_bind_s(self.root_dn, self.root_pw)
        self.binding = True
        return self

    def end(self):
        # self.conn.unbind_s()
        self.binding = False
        return self

    def find(self, entry):
        binding = self.binding
        if not binding:
            self.begin()
        result = None
        if entry.dn is None and entry.idx_field is not None and entry.idx_value is not None:
            entry.dn = entry.dn_template % (entry.idx_field, entry.idx_value, entry.branch_part, GLOBAL_LDAP_CONFIG.BASE_DN)
        if entry.dn is not None:
            result = self.conn.search_s(entry.dn, ldap.SCOPE_BASE, '(objectClass=*)')
            if len(result) > 0:
                result = result[0]
                result = entry.__class__.parse(result)
        for field in entry.id_attr_names:
            if result is not None:
                break
            if field in entry.attrs and entry.attrs[field] is not None:
                values = entry.attrs[field] if isinstance(entry.attrs[field], list) else [entry.attrs[field]]
                for value in values:
                    if result is not None:
                        break
                    result = self.search(
                        entry.branch_dn_template % (entry.branch_part, GLOBAL_LDAP_CONFIG.BASE_DN),
                        entry.__class__,
                        filters='%s=%s' % (field, value)
                    )
                    if result is not None and len(result) > 0:
                        result = result[0]
                    else:
                        result = None
        if not binding:
            self.end()
        if result is not None:
            result.cache_attrs()
        return result

    def search(self, base_dn, entity_class, filters=None):
        binding = self.binding
        if not binding:
            self.begin()
        try:
            if filters is None:
                filters = 'objectClass=*'
            results = self.conn.search_s(base_dn, ldap.SCOPE_SUBTREE, '(%s)' % filters)
            if results is None:
                if not binding:
                    self.end()
                return []
            if entity_class is None:
                entity_class = LdapEntity
            result_set = []
            for dn, entry in results:
                result_set.append(entity_class.parse((dn, entry)))
            if not binding:
                self.end()
            return result_set
        except ldap.NO_SUCH_OBJECT:
            if not binding:
                self.end()
            return []

    def add_entry(self, entry):
        binding = self.binding
        if not binding:
            self.begin()
        if entry.is_ldap_attr('ftId') and 'ftId' not in entry.attrs:
            entry.attrs['ftId'] = str(object_id_to_uuid(ObjectId()))
        must_attr_names = GLOBAL_LDAP_CONFIG.MUST_ATTR_NAMES.get(entry.__class__.__name__, [])
        for must_attr_name in must_attr_names:
            if must_attr_name.lower() != entry.idx_field.lower() \
                    and must_attr_name.lower() != 'objectclass' \
                    and must_attr_name not in entry.attrs:
                raise ldap.OBJECT_CLASS_VIOLATION('Missing Attribute: %s' % must_attr_name)
        self.conn.add_s(entry.dn, entry.add_modlist())
        if not binding:
            self.end()
        return self

    def save_entry(self, entry):
        binding = self.binding
        if not binding:
            self.begin()
        self.conn.modify_s(entry.dn, entry.modify_modlist())
        if not binding:
            self.end()
        return self

    def load_object_classes(self, schema_names):
        """加载Schema Object Class"""
        subschema_subentry_dn, schema = ldap.schema.urlfetch(GLOBAL_LDAP_CONFIG.LDAP_URL)
        for schema_name in schema_names:
            schema_attr_obj = schema.get_obj(ldap.schema.ObjectClass, schema_name)
            if schema_attr_obj is not None:
                GLOBAL_LDAP_CONFIG.OBJECT_CLASSES[schema_name] = schema_attr_obj

    def get_object_classes(self, schema_names):
        """根据对象名列表加载所有对象Schema"""
        missing = set()
        for schema_name in schema_names:
            if schema_name not in GLOBAL_LDAP_CONFIG.OBJECT_CLASSES:
                missing.add(schema_name)
        if len(missing) > 0:
            self.load_object_classes(missing)
        object_classes = set()
        for schema_name in schema_names:
            if schema_name in GLOBAL_LDAP_CONFIG.OBJECT_CLASSES:
                object_classes.add(GLOBAL_LDAP_CONFIG.OBJECT_CLASSES[schema_name])
        return object_classes

    def get_must_attributes(self, schema_names):
        """返回所有必须属性"""
        object_classes = self.get_object_classes(schema_names)
        return list(reduce(operator.add, map(lambda obj: obj.must, object_classes)))

    def get_may_attributes(self, schema_names):
        """返回所有可选属性"""
        object_classes = self.get_object_classes(schema_names)
        return list(reduce(operator.add, map(lambda obj: obj.may, object_classes)))

    def register_entity_class(self, entity_class):
        """注册实体对象类"""
        binding = self.binding
        if not binding:
            self.begin()
        dn = entity_class.branch_dn_template % (entity_class.branch_part, GLOBAL_LDAP_CONFIG.BASE_DN)
        branch_entity = self.find(BranchEntity(dn=dn))
        class_name = entity_class.__name__
        if branch_entity is None:
            branch_entity = BranchEntity(dn, attrs={
                'objectClass': entity_class.branch_class,
                'description': entity_class.branch_description
            })
            self.add_entry(branch_entity)
        GLOBAL_LDAP_CONFIG.MUST_ATTR_NAMES[class_name] = map(
            str.lower,
            self.get_must_attributes(entity_class.object_class))
        # print class_name, entity_class.object_class, GLOBAL_LDAP_CONFIG.MUST_ATTR_NAMES[class_name]
        GLOBAL_LDAP_CONFIG.MAY_ATTR_NAMES[class_name] = map(
            str.lower,
            self.get_may_attributes(entity_class.object_class))
        GLOBAL_LDAP_CONFIG.VALID_ATTR_NAMES[class_name] = list(
            set(GLOBAL_LDAP_CONFIG.MUST_ATTR_NAMES[class_name] + GLOBAL_LDAP_CONFIG.MAY_ATTR_NAMES[class_name])
        )
        if not binding:
            self.end()
        return self


GLOBAL_LDAP_CONNECTION = LdapConnection()
