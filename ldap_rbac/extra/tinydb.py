# -*- coding: utf-8 -*-
from resources import ResourceHelper
from acls import AccessControlListHelper
from tags import TagsHelper


class TinyDbAccessControlList(AccessControlListHelper):
    def __init__(self, db=None, table=None):
        self.db = db


class TinyDbTags(TagsHelper):
    def __init__(self, db=None, table=None):
        self.db = db


class TinyDbLogger(object):
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

    def filter_of_user(self, user=None):
        pass

    def instance(self, parent=None, name=None, **kwargs):
        pass

    def find_one(self, path=None, rid=None, **kwargs):
        pass