# -*- coding: utf-8 -*-
from flask import Blueprint

group_manager = Blueprint('ldap_login', __name__)


def add_group(group):
    pass


def add_group_property(group, key, value):
    pass


def assign_group(group, member):
    pass


def deassign_group(group, member):
    pass


def delete_group(group, key=None, value=None):
    pass


def find_groups(group=None, user=None):
    pass


def read_group(group):
    pass


def update_group(group):
    pass