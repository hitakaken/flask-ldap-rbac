# -*- coding: utf-8 -*-
from flask import Blueprint

access_manager = Blueprint('accessMgr', __name__)


@access_manager.route('/authenticate')
def authenticate(username, password):
    pass


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
