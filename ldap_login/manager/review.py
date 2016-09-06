# -*- coding: utf-8 -*-
from flask import Blueprint

review_manager = Blueprint('ldap_login', __name__)

def assigned_roles(user):
    pass


def assigned_users(role, limit=0):
    pass


def authorized_permission_roles(permission):
    pass


def authorized_permission_users(permission):
    pass


def authorized_roles(user):
    pass


def authorized_users(role):
    pass


def find_any_permissions(permission):
    pass


def find_permissions(permission):
    pass


def find_permission_objects(ou=None, permission_object=None):
    pass


def find_permissions_by_object(permission_object):
    pass


def find_roles(role, limit=0):
    pass


def find_users(ou=None, user=None, limit=0):
    pass


def permission_roles(permission):
    pass


def permission_users(permission):
    pass


def read_permission(permission):
    pass


def read_permission_object(permission_object):
    pass


def read_role(role):
    pass


def read_user(user):
    pass


def role_permissions(role, inheritance=True):
    pass


def user_permissions(user):
    pass