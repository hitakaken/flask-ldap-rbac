# -*- coding: utf-8 -*-
# https://zh.wikipedia.org/wiki/HTTP%E7%8A%B6%E6%80%81%E7%A0%81


class RuntimeException(Exception):
    state_code = 500


class UserNotFound(RuntimeException):
    state_code = 404


class UserAlreadyExists(RuntimeException):
    state_code = 409


class InvalidCredentials(RuntimeException):
    state_code = 403


