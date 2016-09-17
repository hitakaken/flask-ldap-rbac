# -*- coding: utf-8 -*-
# https://directory.apache.org/fortress/gen-docs/1.0.1/apidocs/org/apache/directory/fortress/core/AccessMgr.html
from ldap_rbac.patched import Namespace, Resource, fields, cors
from ldap_rbac.exceptions import UserNotFound, InvalidCredentials
from ldap_rbac.models import context, users

api = Namespace('access',
                title='Access Manager',
                version='1.0',
                description='',
                tags=['access']
                )


@api.route('/authenticate')
class Authenticate(Resource):

    @api.expect(context.credential)
    @api.marshal_with(context.token)
    # @cors.crossdomain(origin='*')
    def post(self):
        """
        Authenticate

        :raises UserNotFound: User not found
        :raises InvalidCredentials: Password Error
        """
        credential = context.credential.parse_args()
        user = users.authenticate({'sn': credential['name']}, credential['password'])
        return {
            'token': context.encode({

            })
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
