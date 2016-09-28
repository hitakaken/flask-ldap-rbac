# -*- coding: utf-8 -*-
from resources import ResourceHelper
from acls import AccessControlListHelper
from tags import TagsHelper


class TinyDbResources(ResourceHelper):
    def __init__(self, root=None, acls=None, tags=None, logger=None,
                 db=None, enable_acl=True, enable_tags=True, enable_log=True,
                 enable_access_log=True, enable_operation_log=False):
        super(TinyDbResources, self).__init__(root=root, acls=acls, tags=tags, logger=logger)

    def instance(self, parent=None, name=None, **kwargs):
        pass


class TinyDbAccessControlList(AccessControlListHelper):
    def __init__(self):
        pass


class TinyDbTags(TagsHelper):
    def __init__(self):
        pass


class TinyDbLogger(object):
    def __init__(self):
        pass

