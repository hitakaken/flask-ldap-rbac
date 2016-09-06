# -*- coding: utf-8 -*-
import operator
from ldap_login.models.helper import GLOBAL_LDAP_CONNECTION
from ldap_login.models.base import Config
from ldap_login.models.users import User
from ldap_login.models.rbac import Policy, RBAC, Constraint
from ldap_login.models.roles import Role
from ldap_login.models.permissions import PermObj


def initialize(ldap_config):
    """初始化"""
    GLOBAL_LDAP_CONNECTION.init_config(ldap_config)
    GLOBAL_LDAP_CONNECTION.begin()
    entity_classes = [Config, User, Policy, RBAC, Role, PermObj, Constraint]
    schema_names = set()
    for entity_class in entity_classes:
        for object_class in entity_class.object_class:
            schema_names.add(object_class)
    GLOBAL_LDAP_CONNECTION.load_object_classes(list(schema_names))
    for entity_class in entity_classes:
        GLOBAL_LDAP_CONNECTION.register_entity_class(entity_class)
    GLOBAL_LDAP_CONNECTION.end()

