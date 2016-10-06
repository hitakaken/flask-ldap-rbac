# -*- coding: utf-8 -*-
from ldap_rbac.resources.logger import ResourceLogger


class TinyLogger(ResourceLogger):
    def __init__(self, db=None, table=None):
        self.db = db
        self.table = table

    def log(self, resource, event=None, user=None, **kwargs):
        pass