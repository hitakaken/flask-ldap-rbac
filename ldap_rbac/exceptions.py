# -*- coding: utf-8 -*-
# https://zh.wikipedia.org/wiki/HTTP%E7%8A%B6%E6%80%81%E7%A0%81
from werkzeug.exceptions import BadRequest, ClientDisconnected, SecurityError, BadHost, \
    Unauthorized, Forbidden, NotFound, MethodNotAllowed, NotAcceptable, RequestTimeout, Conflict, Gone, LengthRequired
from ldap_rbac.patched import Namespace, fields

api = Namespace('Error', description='错误')
error = api.model('Error', {
    'message': fields.String,
})


class RuntimeException(Exception):
    state_code = 500


class UserNotFound(RuntimeException):
    state_code = 404


@api.errorhandler(UserNotFound)
@api.marshal_with(error, code=404)
def handle_user_not_found_exception(error):
    """Return a custom message and 404 status code"""
    return {'message': UserNotFound.message}, UserNotFound.state_code


class UserAlreadyExists(RuntimeException):
    state_code = 409


class InvalidCredentials(RuntimeException):
    state_code = 403


@api.errorhandler(InvalidCredentials)
@api.marshal_with(error, code=403)
def handle_invalid_credentials_exception(error):
    """Return a custom message and 403 status code"""
    return {'message': InvalidCredentials.message}, InvalidCredentials.state_code


class TokenDecodeError(RuntimeException):
    state_code = 403


class TokenExpired(RuntimeException):
    state_code = 403


