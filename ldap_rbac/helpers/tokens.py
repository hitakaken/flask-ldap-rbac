# -*- coding: utf-8 -*-
import datetime
from ldap_rbac.core import constants, exceptions
from ldap_rbac.models import TokenUser
import jwt
import msgpack


def get_callback_function(func, default_function=None, default_return=None):
    if (func is None and default_function is None) or not callable(func):
        func_return = func if func is not None else default_return

        def return_func(input, **kwargs):
            return func_return

        return return_func
    return func if func is not None else default_function


class TokenHelper(object):
    def __init__(self, jwt_config=None, token_config=None):
        if jwt_config is None:
            jwt_config = {}
        if token_config is None:
            token_config = {}
        self.jwt_secret = get_callback_function(jwt_config.get('secret', constants.JWT_SECRET))
        self.jwt_algorithm = get_callback_function(jwt_config.get('algorithm', constants.JWT_ALGORITHM))
        self.jwt_expired = get_callback_function(jwt_config.get('expired', constants.JWT_EXPIRED_TIMEDELTA))
        self.jwt_leeway = get_callback_function(jwt_config.get('leeway', constants.JWT_LEEWAY))
        self.token_header = token_config.get('HEADER', 'AUTH')

    def encode(self, payload, **kwargs):
        """生成JWT令牌"""
        secret = self.jwt_secret(payload, **kwargs)
        algorithm = self.jwt_algorithm(payload, **kwargs)
        # iat = datetime.datetime.utcnow()
        if 'exp' not in payload:
            expired = datetime.datetime.utcnow() + self.jwt_expired(payload, **kwargs)
            payload['exp'] = expired
        jwt_token = jwt.encode(payload, secret, algorithm=algorithm, **kwargs)
        return jwt_token

    def decode(self, jwt_token, **kwargs):
        """解码JWT令牌"""
        secret = self.jwt_secret(jwt_token, **kwargs)
        algorithm = self.jwt_algorithm(jwt_token, **kwargs)
        try:
            leeway = self.jwt_leeway(jwt_token, **kwargs)
            return jwt.decode(jwt_token, secret, algorithms=[algorithm], leeway=leeway, **kwargs)
        except jwt.ExpiredSignatureError:
            # Signature has expired
            raise exceptions.TOKEN_EXPIRED
        except jwt.DecodeError:
            raise exceptions.TOKEN_DECODE_ERROR

    def encrypt(self, content, **kwargs):
        return msgpack.packb(content, **kwargs)

    def decrypt(self, encrypted, **kwargs):
        return msgpack.unpackb(encrypted, **kwargs)

    def load_user_from_request(self, request):
        payload = self.decode(request.headers.get(self.token_header))
        info = self.decrypt(payload.get('info'))
        return TokenUser(name=payload.get('name'), uid=info.get('id'), roles=info.get('roles'), helper=self)

    def token_user(self, user):
        return TokenUser(name=user.name, uid=user.id, roles=user.roles, helper=self)

    def token(self, user):
        user = self.token_user(user)
        return self.decode({
            'name': user.name,
            'info': self.encrypt({
                'id': user.id,
                'roles': user.roles
            })
        })
