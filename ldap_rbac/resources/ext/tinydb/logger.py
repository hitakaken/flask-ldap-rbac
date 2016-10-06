# -*- coding: utf-8 -*-
from ldap_rbac.core import utils
from ldap_rbac.resources.logger import ResourceLogger


class TinyLogger(ResourceLogger):
    def __init__(self, db=None, table=None):
        self.db = db
        self.table = table

    def db(self):
        return self.table if self.table is not None else self.db

    def log(self, resource, event=None, user=None, **kwargs):
        self.db().insert({
            'uuid': utils.uuid(),
            'rid': resource.rid,
            'uid': user.id,
            'evt': event
        })
