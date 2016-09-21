# -*- coding: utf-8 -*-
from flask import Blueprint
from ldap_rbac.patched import Namespace, Resource, fields, cors
from ldap_rbac.exceptions import UserNotFound, InvalidCredentials
from ldap_rbac.models import context, users

api = Namespace('admin',
                title='Admin Manager',
                version='1.0',
                description='',
                tags=['admin']
                )


@api.route('/add_user/')
class AddUser(Resource):
    @api.expect(context.credential)
    @api.marshal_with(context.token)
    # @cors.crossdomain(origin='*')
    def post(self):
        if not users.read(user):
            return users.create(user)
        raise UserWarning


def disable_user(user):
    pass


def delete_user(user):
    pass


def update_user(user):
    pass


def change_password(user, password):
    pass


def lock_user_account(user):
    pass


def unlock_user_account(user):
    pass


def reset_password(user, password):
    pass


def delete_password_policy(user):
    pass


def add_role(role):
    pass


def delete_role(role):
    pass


def update_role(role):
    pass


def assign_user(user_role):
    pass


def deassign_user(user_role):
    pass


def add_permission(permission):
    pass


def update_permission(permission):
    pass


def delete_permission(permission):
    pass


def add_permission_object(permission_object):
    pass


def update_permission_object(permission_object):
    pass


def delete_permission_object(permission_object):
    pass


def grant_permission(permission, role=None, user=None):
    pass


def revoke_permission(permission, role=None, user=None):
    pass


def add_descendant(parent_role, child_role):
    pass


def add_ascendant(child_role, parent_role):
    pass


def add_inheritance(parent_role, child_role):
    pass


def delete_inheritance(parent_role, child_role):
    pass
