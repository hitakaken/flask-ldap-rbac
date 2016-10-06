# -*- coding: utf-8 -*-
from tinydb import Query
from ldap_rbac.resources.acls import AccessControlList, AccessControlListHelper


class TinyACLs(AccessControlListHelper):
    def __init__(self, db=None, table=None):
        self.db = db
        self.table = table

    @property
    def type(self):
        return 'TinyDB'

    def db(self):
        return self.table if self.table is not None else self.db

    def load(self, resource, force=False):
        if resource.loaded_acls is not None and not force:
            return
        if resource.helper.is_acl_together:
            aces = resource.underlying.get('acls', {})
        else:
            query = Query()
            result = self.db().get(query.rid == resource.rid)
            aces = {} if result is None else result.get('acls', {})
        resource.loaded_acls = AccessControlList(aces=aces)

    def save(self, resource):
        if resource.helper.is_acl_together:
            resource.underlying['acls'] = dict(resource.loaded_acls)
        else:
            query = Query()
            if (self.db().get(query.rid == resource.rid)) is None:
                self.db().insert({
                    'rid': resource.rid,
                    'acls': dict(resource.loaded_acls)
                })
            else:
                self.db().update({'acls': dict(resource.loaded_acls)}, query.rid == resource.rid)


