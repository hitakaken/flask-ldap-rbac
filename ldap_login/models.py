# -*- coding: utf-8 -*-
import ldap
import ldap.modlist
import ldap.schema
import operator

# 全局变量
GLOBAL_LDAP_URL = 'ldap://127.0.0.1'
GLOBAL_OBJECT_CLASSES = {}
GLOBAL_BASE_DN = 'dc=novbase,dc=com'
GLOBAL_DESCRIPTION = 'NovBase Software'


def load_object_classes(schema_names):
    """加载Schema Object Class"""
    global GLOBAL_LDAP_URL, GLOBAL_OBJECT_CLASSES
    subschema_subentry_dn, schema = ldap.schema.urlfetch(GLOBAL_LDAP_URL)
    for schema_name in schema_names:
        schema_attr_obj = schema.get_obj(ldap.schema.ObjectClass, schema_name)
        if schema_attr_obj is not None:
            GLOBAL_OBJECT_CLASSES[schema_name] = schema_attr_obj


def get_object_classes(schema_names):
    """根据对象名列表加载所有对象Schema"""
    global GLOBAL_OBJECT_CLASSES
    missing = set()
    for schema_name in schema_names:
        if schema_name not in GLOBAL_OBJECT_CLASSES:
            missing.add(schema_name)
    if len(missing) > 0:
        load_object_classes(missing)
    object_classes = set()
    for schema_name in schema_names:
        if schema_name in GLOBAL_OBJECT_CLASSES:
            object_classes.add(GLOBAL_OBJECT_CLASSES[schema_name])
    return object_classes


def get_must_attributes(schema_names):
    """返回所有必须属性"""
    object_classes = get_object_classes(schema_names)
    return list(reduce(operator.add, map(lambda obj: obj.must, object_classes)))


def get_may_attributes(schema_names):
    """返回所有可选属性"""
    object_classes = get_object_classes(schema_names)
    return list(reduce(operator.add, map(lambda obj: obj.may, object_classes)))


def convert_dn_to_list(dn):
    return [n.split('=') for n in dn.split(',')]


# Schema Name, Schema DN, Schema Description, objectClasses
schemas = [
    ('Config', 'ou=Config', 'Fortress People',
     ['device', 'ftProperties']),
    ('User', 'ou=People', 'Fortress People',
     []),
    ('Policy', 'ou=Policies', 'Fortress Policies',
     []),
    ('RBAC', 'ou=RBAC', 'Fortress RBAC Policies',
     []),
    ('Role', 'ou=Roles,ou=RBAC', 'Fortress Roles',
     ['top', 'ftRls', 'ftProperties', 'ftMods']),
    ('Permission', 'ou=Permissions,ou=RBAC', 'Fortress Permissions',
     []),
    ('Constraint', 'ou=Constraints,ou=RBAC', 'Fortress Separation of Duty Constraints',
     []),
    ('ARBAC', 'ou=ARBAC', 'Fortress Administrative RBAC Policies',
     []),
    ('OS-U', 'ou=OS-U,ou=ARBAC', 'Fortress User Organizational Units',
     ['top', 'ftOrgUnit', 'ftMods']),
    ('OS-P', 'ou=OS-P,ou=ARBAC', 'Fortress Perm Organizational Units',
     ['top', 'ftOrgUnit', 'ftMods']),
    ('AdminRole', 'ou=AdminRoles,ou=ARBAC', 'Fortress AdminRoles',
     ['top', 'ftRls', 'ftProperties', 'ftPools', 'ftMods']),
    ('AdminPerm', 'ou=AdminPerms,ou=ARBAC', 'Admin Permissions',
     [])
]


def initialize(ldap_connection):
    # 初始化表
    # https://github.com/apache/directory-fortress-core/blob/master/src/test/resources/init-ldap.ldif
    # NOTICE: BASE_DN 必须存在
    global schemas
    for schema in schemas:
        (name, prefix, description) = schema
        dn = '%s,%s' % (prefix, GLOBAL_BASE_DN)
        try:
            ldap_connection.search_s(dn, ldap.SCOPE_BASE, '(objectClass=*)')
        except ldap.NO_SUCH_OBJECT:
            modlist = [  # ldap.modlist.addModlist({
                ('objectClass', 'organizationalUnit'),
                ('ou', convert_dn_to_list(prefix)[0][1]),
                ('description', description)
            ]  # })
            print dn, modlist
            ldap_connection.add_s(dn, modlist)


class FortressEntity(object):
    objectclass = ['ftMods']

    def __init__(self, **kwargs):
        pass


class User(FortressEntity):
    objectclass = ['inetOrgPerson', 'organizationalPerson', 'ftProperties', 'ftUserAttrs', 'ftMods']

    def __init__(self):
        pass


class OrgUnit(object):
    objectclass = ['organizationalUnit', 'ftOrgUnit', 'ftMods']

    def __init__(self):
        pass


class Administrator(object):
    def __init__(self):
        pass


class RoleMixin(object):
    objectclass = ['organizationalRole', 'ftRls', 'ftProperties', 'ftMods']
    roles = {}

    def __init__(self):
        pass


class UserRole(object):
    objectclass = ['ftUserAttrs']

    def __init__(self):
        pass


class PermissionMixin(object):
    objectclass = ['ftOperation', 'ftProperties', 'ftMods']

    def __init__(self):
        pass


class PermissionObjectMixin(object):
    objectclass = ['ftObject', 'ftProperties', 'ftMods']

    def __init__(self):
        pass


class Token(object):
    def __init__(self):
        pass
