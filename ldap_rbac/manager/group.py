# -*- coding: utf-8 -*-
from ldap_rbac.patched import Namespace

api = Namespace('group',
                title='Group Manager',
                version='1.0',
                description='',
                tags=['group']
                )


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