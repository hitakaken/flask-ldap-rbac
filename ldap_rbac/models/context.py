# -*- coding: utf-8 -*-
import jwt
from ldap_rbac import exceptions
from ldap_rbac.models.helper import GLOBAL_LDAP_CONNECTION
from ldap_rbac.models.base import Config
from ldap_rbac.models.users import User
from ldap_rbac.models.rbac import Policy, RBAC, Constraint
from ldap_rbac.models.roles import Role
from ldap_rbac.models.permissions import PermObj
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

get_secret = None
get_algorithm = None


def encode(content, ext=None):
    secret = 'secret' if get_secret is None else get_secret(content, ext=ext)
    algorithm = 'HS256' if get_algorithm is None else get_algorithm(content, ext=ext)
    return jwt.encode(content, secret, algorithm=algorithm)


def decode(content, ext=None):
    secret = 'secret' if get_secret is None else get_secret(content, ext=ext)
    algorithm = 'HS256' if get_algorithm is None else get_algorithm(content, ext=ext)
    return jwt.decode(content, secret, algorithms=[algorithm])


namespace = Namespace('User', description='用户管理接口')
error = namespace.model('Error', {
    'message': fields.String,
})
credential = reqparse.RequestParser()
credential.add_argument('name', location='form', help='用户名/邮箱/手机号', )
credential.add_argument('password', location='form', type='password', help='密码', )
user = namespace.model('User', {
    'name': fields.String
})
token = namespace.model('Token', {
    'token': fields.String(required=True, description='身份令牌'),
    'user': fields.Nested(user),
    'base': fields.String,
    'admin': fields.String,
    'expired': fields.Integer
})
role = namespace.model('Role', {
    'name': fields.String
})


