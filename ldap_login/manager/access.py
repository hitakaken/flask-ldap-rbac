# -*- coding: utf-8 -*-
# https://directory.apache.org/fortress/gen-docs/1.0.1/apidocs/org/apache/directory/fortress/core/AccessMgr.html
from flask import Blueprint
from flask_restplus import Api, Namespace, Resource, fields
from ldap_login.models import context

access_manager = Blueprint('accessMgr', __name__)
api = Api(
    access_manager,
    title='Access Manager',
    version='1.0',
    description=''
)
api.add_namespace(context.namespace)


@api.route('/access/authn')
class authenticate(Resource):
    @api.expect(context.credential_model)
    @api.marshal_with(context.token_model)
    def post(self):
        return {
            'token': 'afdsafasd'
        }


def create_token(user, trusted=True):
    pass


def check_access(token, permission):
    pass


def token_permissions(token):
    pass


def token_roles(token):
    pass


def authorized_roles(token):
    pass


def add_active_role(token, user_role):
    pass


def drop_active_role(token, user_role):
    pass


def get_user_id(token):
    pass


def get_user(token):
    pass
