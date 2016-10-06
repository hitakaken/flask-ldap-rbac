# -*- coding: utf-8 -*-
# https://directory.apache.org/fortress/gen-docs/1.0.1/apidocs/org/apache/directory/fortress/core/AccessMgr.html
from flask import current_app as app
from flask_restplus import reqparse
from ldap_rbac.patched import Namespace, Resource, fields, cors
from ldap_rbac.core.exceptions import SecurityException

api = Namespace('access',
                title='Access Manager',
                version='1.0',
                description='',
                tags=['access']
                )

credential_request = reqparse.RequestParser()
credential_request.add_argument('username', location='form')
credential_request.add_argument('password', location='form')
token_response = api.model('Token', {
    'token': fields.String
})


@api.route('/authenticate')
class Authenticate(Resource):
    @api.expect(credential_request)
    @api.marshal_with(token_response)
    # @cors.crossdomain(origin='*')
    def post(self):
        """
        Authenticate


        :raises SecurityException: Authenticate Failed
        """

        global credential_request
        args = credential_request.parse_args()
        user = app.rbac.users.authenticate(args['username'], args['password'])
        return {'token': app.rbac.tokens.token(user)}


token_request = reqparse.RequestParser()
token_request.add_argument('token', location='form')


@api.route('/check')
class CheckToken(Resource):

    @api.expect(token_request)
    @api.marshal_with(token_response)
    def post(self):
        """
        Check Token


        :raises SecurityException: Check Token Failed
        """

        global token_request
        args = token_request.parse_args()
        user = app.rbac.tokens.load_user_from_token(args['token'])
        return {'token': args['token']}


@api.route('/refresh')
class RefreshToken(Resource):

    @api.expect(token_request)
    @api.marshal_with(token_response)
    def post(self):
        """
        Refresh Token


        :raises SecurityException: Refresh Token Failed
        """

        global token_request
        args = token_request.parse_args()
        user = app.rbac.tokens.load_user_from_token(args['token'])
        return {'token': app.rbac.tokens.token(user)}


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
