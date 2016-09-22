# -*- coding: utf-8 -*-
import ldap
import ldap.schema
import operator


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


class LdapConnection(object):
    def __init__(self, ldap_config=None):
        self.conn = None
        self.auth_conn = None
        self.root_dn = None
        self.root_pw = None
        self.binding = False
        self.config = LdapConfig()

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
        self.root_dn = ldap_config['ROOT_DN']
        self.root_pw = ldap_config['ROOT_PW']
        self.config.BASE_DN = ldap_config.get('BASE_DN', self.config.BASE_DN)

    def begin(self):
        self.conn.simple_bind_s(self.root_dn, self.root_pw)
        self.binding = True
        return self

    def end(self):
        # self.conn.unbind_s()
        self.binding = False
        return self


class BaseLdapCollection(object):
    idx_field = 'cn'
    idx_value = None
    attrs = {}
    cached_attrs = {}
    object_class = []
    id_attr_names = ['ftId']
    ignore_modify_attr_types = ['userPassword']
    mapping = bidict()

    def __init__(self, ldap_connection):
        self.ldap = ldap_connection

    def get_dn(self, entry):


    def find(self, entry):
        binding = self.ldap.binding
        if not binding:
            self.ldap.begin()
        result = None
        if entry.dn is None and entry.idx_field is not None and entry.idx_value is not None:
            entry.dn = entry.dn_template % (entry.idx_field, entry.idx_value, entry.branch_part, GLOBAL_LDAP_CONFIG.BASE_DN)
        if entry.dn is not None:
            try:
                result = self.ldap.conn.search_s(entry.dn, ldap.SCOPE_BASE, '(objectClass=*)')
            except ldap.NO_SUCH_OBJECT:
                result = None
            if result is not None and len(result) > 0:
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
                        entry.branch_dn_template % (entry.branch_part, self.ldap.config.BASE_DN),
                        entry.__class__,
                        filters='%s=%s' % (field, value)
                    )
                    if result is not None and len(result) > 0:
                        result = result[0]
                    else:
                        result = None
        if not binding:
            self.ldap.end()
        if result is not None:
            result.cache_attrs()
        return result

    def search(self, base_dn, entity_class, filters=None):
        binding = self.ldap.binding
        if not binding:
            self.ldap.begin()
        try:
            if filters is None:
                filters = 'objectClass=*'
            results = self.ldap.conn.search_s(base_dn, ldap.SCOPE_SUBTREE, '(%s)' % filters)
            if results is None:
                if not binding:
                    self.ldap.end()
                return []
            if entity_class is None:
                entity_class = LdapEntity
            result_set = []
            for dn, entry in results:
                result_set.append(entity_class.parse((dn, entry)))
            if not binding:
                self.ldap.end()
            return result_set
        except ldap.NO_SUCH_OBJECT:
            if not binding:
                self.ldap.end()
            return []

    def add_entry(self, entry):
        binding = self.ldap.binding
        if not binding:
            self.ldap.begin()
        if entry.is_ldap_attr('ftId') and 'ftId' not in entry.attrs:
            entry.attrs['ftId'] = str(object_id_to_uuid(ObjectId()))
        must_attr_names = self.ldap.config.MUST_ATTR_NAMES.get(entry.__class__.__name__, [])
        for must_attr_name in must_attr_names:
            if must_attr_name.lower() != entry.idx_field.lower() \
                    and must_attr_name.lower() != 'objectclass' \
                    and must_attr_name not in entry.attrs:
                raise ldap.OBJECT_CLASS_VIOLATION('Missing Attribute: %s' % must_attr_name)
        self.ldap.conn.add_s(entry.dn, entry.add_modlist())
        if not binding:
            self.ldap.end()
        return self

    def save_entry(self, entry):
        binding = self.ldap.binding
        if not binding:
            self.ldap.begin()
        self.ldap.conn.modify_s(entry.dn, entry.modify_modlist())
        if not binding:
            self.ldap.end()
        return self

    def load_object_classes(self, schema_names):
        """加载Schema Object Class"""
        subschema_subentry_dn, schema = ldap.schema.urlfetch(self.ldap.config.LDAP_URL)
        for schema_name in schema_names:
            schema_attr_obj = schema.get_obj(ldap.schema.ObjectClass, schema_name)
            if schema_attr_obj is not None:
                self.ldap.config.OBJECT_CLASSES[schema_name] = schema_attr_obj

    def get_object_classes(self, schema_names):
        """根据对象名列表加载所有对象Schema"""
        missing = set()
        for schema_name in schema_names:
            if schema_name not in self.ldap.config.OBJECT_CLASSES:
                missing.add(schema_name)
        if len(missing) > 0:
            self.load_object_classes(missing)
        object_classes = set()
        for schema_name in schema_names:
            if schema_name in self.ldap.config.OBJECT_CLASSES:
                object_classes.add(self.ldap.config.OBJECT_CLASSES[schema_name])
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
        binding = self.ldap.binding
        if not binding:
            self.ldap.begin()
        dn = entity_class.branch_dn_template % (entity_class.branch_part, self.ldap.config.BASE_DN)
        branch_entity = self.find(BranchEntity(dn=dn))
        class_name = entity_class.__name__
        if branch_entity is None:
            branch_entity = BranchEntity(dn, attrs={
                'objectClass': entity_class.branch_class,
                'description': entity_class.branch_description
            })
            self.add_entry(branch_entity)
        self.ldap.config.MUST_ATTR_NAMES[class_name] = map(
            str.lower,
            self.get_must_attributes(entity_class.object_class))
        # print class_name, entity_class.object_class, GLOBAL_LDAP_CONFIG.MUST_ATTR_NAMES[class_name]
        self.ldap.config.MAY_ATTR_NAMES[class_name] = map(
            str.lower,
            self.get_may_attributes(entity_class.object_class))
        self.ldap.config.VALID_ATTR_NAMES[class_name] = list(
            set(self.ldap.config.MUST_ATTR_NAMES[class_name] + self.ldap.config.MAY_ATTR_NAMES[class_name])
        )
        if not binding:
            self.ldap.end()
        return self