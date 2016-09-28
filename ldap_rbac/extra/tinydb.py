# -*- coding: utf-8 -*-
from resources import ResourceHelper
from acls import AccessControlListHelper
from tags import TagsHelper
from logger import ResourceLogger


class TinyDbAccessControlList(AccessControlListHelper):
    def __init__(self, db=None, table=None):
        self.db = db

    def load(self, resource, force=False):
        pass

    def add(self, resource, aces, user=None):
        pass

    def remove(self, resource, aces, user=None):
        pass

    def clear(self, resource):
        pass

    def save(self, resource):
        pass


class TinyDbTags(TagsHelper):
    def __init__(self, db=None, table=None):
        self.db = db

    def load(self, resource, force=False):
        pass

    def add(self, resource, tags, user=None):
        pass

    def remove(self, resource, tags, user=None):
        pass

    def clear(self, resource):
        pass

    def save(self, resource):
        pass


class TinyDbLogger(ResourceLogger):
    def __init__(self, db=None, table=None):
        self.db = db

    def log(self, resource, event=None, user=None, **kwargs):
        pass


class TinyDbResources(ResourceHelper):
    def __init__(self, root=None, acls=None, tags=None, logger=None,
                 db=None, enable_acl=True, enable_tags=True, enable_log=True,
                 enable_access_log=True, enable_operation_log=False):
        self.db = db
        if enable_acl and acls is None:
            acls = TinyDbAccessControlList(db=db)
        if enable_tags and tags is None:
            acls = TinyDbTags(db=db)
        if enable_log and logger is None:
            acls = TinyDbLogger(db=db)
        super(TinyDbResources, self).__init__(
            root=root,
            acls=acls, tags=tags, logger=logger,
            enable_access_log=enable_access_log, enable_operation_log=enable_operation_log)

    def query_of_user(self, user=None):
        pass

    def query(self, dsl):
        pass

    def instance(self, parent=None, name=None, **kwargs):
        pass

    def create(self, resource, user=None, **kwargs):
        pass

    def find_by_path(self, path, **kwargs):
        pass

    def find_by_id(self, rid, **kwargs):
        pass

    def find_all(self, query, **kwargs):
        pass

    def count(self, query, **kwargs):
        pass

    def update(self, resource, user=None, **kwargs):
        pass

    def delete(self, path, user=None, **kwargs):
        pass

    def update_xattrs(self, resource, xattrs):
        pass

    def load_xattrs(self, resource):
        pass

    def clear_xattrs(self, resource):
        pass

    def remove_xattrs(self, resource, keys):
        pass
