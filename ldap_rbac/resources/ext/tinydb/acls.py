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
            ace_text_list = resource.underlying.get('acls', [])
        else:
            query = Query()
            result = self.db().get(query.rid == resource.rid)
            ace_text_list = [] if result is None else result.get('acls', [])
        resource.loaded_acls = AccessControlList(ace_text_list=ace_text_list)

    def save(self, resource):
        if resource.helper.is_acl_together:
            resource.underlying['acls'] = resource.loaded_acls.to_list
        else:
            query = Query()
            if (self.db().get(query.rid == resource.rid)) is None:
                self.db().insert({
                    'rid': resource.rid,
                    'acls': resource.loaded_acls.to_list
                })
            else:
                self.db().update({'acls': resource.loaded_acls.to_list}, query.rid == resource.rid)


