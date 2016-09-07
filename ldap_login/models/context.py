# -*- coding: utf-8 -*-
from ldap_login.models.helper import GLOBAL_LDAP_CONNECTION
from ldap_login.models.base import Config
from ldap_login.models.users import User
from ldap_login.models.rbac import Policy, RBAC, Constraint
from ldap_login.models.roles import Role
from ldap_login.models.permissions import PermObj
from flask_restplus import Namespace, fields, reqparse


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

namespace = Namespace('User', description='用户管理接口')
credential_model = reqparse.RequestParser()
credential_model.add_argument('name', location='form', help='用户名/邮箱/手机号', )
credential_model.add_argument('password', location='form', type='password', help='密码', )

user_model = namespace.model('User', {
    'name': fields.String
})
token_model = namespace.model('Token', {
    'token': fields.String(required=True, description='身份令牌'),
    'base': fields.String,
    'admin': fields.String,
    'expired': fields.Integer
})
role_model = namespace.model('Role', {
    'name': fields.String
})

