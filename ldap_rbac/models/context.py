# -*- coding: utf-8 -*-
import datetime
import jwt
import msgpack

from ldap_rbac import defaults, exceptions
from ldap_rbac.models.helper import GLOBAL_LDAP_CONNECTION
from ldap_rbac.models.base import Config
from ldap_rbac.models.users import User
from ldap_rbac.models.rbac import Policy, RBAC, Constraint
from ldap_rbac.models.roles import Role
from ldap_rbac.models.permissions import PermObj
from flask_restplus import Namespace, fields, reqparse

# JWT加密密码获取方式
GET_JWT_SECRET = None
# JWT加密算法
GET_JWT_ALGORITHM = None
GET_JWT_EXPIRED = None
GET_JWT_LEEWAY = None


def encode(payload, **kwargs):
    """生成JWT令牌"""
    secret = defaults.JWT_SECRET if GET_JWT_SECRET is None else GET_JWT_SECRET(payload, **kwargs)
    algorithm = defaults.JWT_ALGORITHM if GET_JWT_ALGORITHM is None else GET_JWT_ALGORITHM(payload, **kwargs)
    # iat = datetime.datetime.utcnow()
    if 'exp' not in payload:
        expired = (datetime.datetime.utcnow() + defaults.JWT_EXPIRED_TIMEDELTA) if GET_JWT_EXPIRED is None \
            else GET_JWT_EXPIRED(payload, **kwargs)
        payload['exp'] = expired
    jwt_token = jwt.encode(payload, secret, algorithm=algorithm, **kwargs)
    return jwt_token


def decode(jwt_token, **kwargs):
    """解码JWT令牌"""
    secret = defaults.JWT_SECRET if GET_JWT_SECRET is None else GET_JWT_SECRET(jwt_token, **kwargs)
    algorithm = defaults.JWT_ALGORITHM if GET_JWT_ALGORITHM is None else GET_JWT_ALGORITHM(jwt_token, **kwargs)
    try:
        leeway = defaults.JWT_LEEWAY if GET_JWT_LEEWAY is None else GET_JWT_LEEWAY(jwt_token, **kwargs)
        return jwt.decode(jwt_token, secret, algorithms=[algorithm], leeway=leeway, **kwargs)
    except jwt.ExpiredSignatureError:
        # Signature has expired
        raise exceptions.TokenExpired()
    except jwt.DecodeError:
        raise exceptions.TokenDecodeError()


def encrypt(content, **kwargs):
    return msgpack.packb(content, **kwargs)


def decrypt(encrypted, **kwargs):
    return msgpack.unpackb(encrypted, **kwargs)


namespace = Namespace('User', description='用户管理接口')
credential = reqparse.RequestParser()
credential.add_argument('name', location='form', help='用户名/邮箱/手机号', )
credential.add_argument('password', location='form', type='password', help='密码', )
user = namespace.model('User', {
    'name': fields.String
})
token = namespace.model('Token', {
    'token': fields.String(required=True, description='身份令牌')
})
role = namespace.model('Role', {
    'name': fields.String
})


def initialize_ldap(ldap_config):
    """初始化LDAP"""
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


def initialize_jwt(jwt_config):
    """初始化JWT"""
    global GET_JWT_SECRET, GET_JWT_ALGORITHM, GET_JWT_EXPIRED, GET_JWT_LEEWAY
    if 'secret' in jwt_config:
        if callable(jwt_config['secret']):
            GET_JWT_SECRET = jwt_config['secret']
        else:
            secret = jwt_config['secret']

            def get_jwt_secret(payload, **kwargs):
                return secret

            GET_JWT_SECRET = get_jwt_secret
    if 'algorithm' in jwt_config:
        if callable(jwt_config['algorithm']):
            GET_JWT_ALGORITHM = jwt_config['algorithm']
        else:
            algorithm = jwt_config['algorithm']

            def get_jwt_algorithm(payload, **kwargs):
                return algorithm

            GET_JWT_ALGORITHM = get_jwt_algorithm
    if 'expired' in jwt_config:
        if callable(jwt_config['expired']):
            GET_JWT_EXPIRED = jwt_config['expired']
        else:
            expired = jwt_config['expired']

            def get_jwt_expired(payload, **kwargs):
                return expired

            GET_JWT_EXPIRED = get_jwt_expired
    if 'leeway' in jwt_config:
        if callable(jwt_config['leeway']):
            GET_JWT_LEEWAY = jwt_config['leeway']
        else:
            leeway = jwt_config['leeway']

            def get_jwt_leeway(jwt_token, **kwargs):
                return leeway

            GET_JWT_LEEWAY = get_jwt_leeway
