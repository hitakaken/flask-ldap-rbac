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

