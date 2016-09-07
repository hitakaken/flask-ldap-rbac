# -*- coding: utf-8 -*-
# https://directory.apache.org/fortress/gen-docs/1.0.1/apidocs/org/apache/directory/fortress/core/AccessMgr.html
from flask import Blueprint
from flask_restplus import Api, Namespace, Resource, fields, cors
from ldap_login.exceptions import UserNotFound, InvalidCredentials
from ldap_login.models import context, users


access_manager = Blueprint('accessMgr', __name__)
api = Api(
    access_manager,
    title='Access Manager',
    version='1.0',
    description=''
)
api.add_namespace(context.namespace)


@api.errorhandler(UserNotFound)
@api.marshal_with(context.error, code=404)
@api.header('My-Header',  'Some description')
def handle_user_not_found_exception(error):
    """Return a custom message and 404 status code"""
    return {'message': UserNotFound.message}, UserNotFound.state_code


@api.errorhandler(InvalidCredentials)
def handle_invalid_credentials_exception(error):
    """Return a custom message and 403 status code"""
    return {'message': InvalidCredentials.message}, InvalidCredentials.state_code


@api.route('/authenticate')
class Authenticate(Resource):

    @api.expect(context.credential)
    @api.marshal_with(context.token)
    # @cors.crossdomain(origin='*')
    def post(self):
        """
        Authenticate

        :raises UserNotFound: User not found
        """
        credential = context.credential.parse_args()
        user = users.authenticate({'sn': credential['name']}, credential['password'])
        return {
            'user': {
                'name': user.uid,
            },
            'token': context.encode({'uid': user.uid, 'id': user.id}),
            'base': [],
            'admin': []
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
