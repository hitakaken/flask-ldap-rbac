# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod, abstractproperty
from ldap_rbac.core import constants

class Resource(object):
    __metaclass__ = ABCMeta

    def __init__(self, parent=None, name=None, rid=None,
                 owner=None, group=None, mode=None, children=None,
                 ctime=None, mtime=None, atime=None, links=None, blocks=None,
                 helper=None):
        self.parent = parent
        self.name = name
        self.rid = rid
        self.owner = owner
        self.group = group
        self.children = children
        self.mode = mode
        self.ctime = ctime
        self.mtime = mtime
        self.atime = atime
        self.links = links
        self.blocks = blocks
        self.helper = helper
        self.loaded = False
        self.loaded_acls = None
        self.loaded_xattrs = None
        self.loaded_tags = None

    @property
    def acls(self, force=False):
        if self.loaded_acls is None or force:
            self.helper.load_acls(self)
        return self.loaded_acls

    @property
    def xattrs(self, force=False):
        if self.loaded_xattrs is None or force:
            self.helper.load_xattrs(self)
        return self.loaded_xattrs

    @property
    def tags(self, force=False):
        if self.loaded_tags is None or force:
            self.loaded_tags = self.helper.load_tags(self)
        return self.loaded_tags

    def can_read(self, user=None):
        pass

    def can_grant_read(self, user=None):
        pass

    def can_write(self, user=None):
        pass

    def can_grant_write(self, user=None):
        pass

    def can_info(self, user=None):
        pass

    def can_list(self, user=None):
        pass

    def can_read_tags(self, user=None):
        pass

    def can_write_tags(self, user=None):
        pass

    def can_grant_read_tags(self, user=None):
        pass

    def can_grant_write_tags(self, user=None):
        pass

    @property
    def path(self):
        return '%s/%s' % (
            '' if self.parent is None else self.parent.path,
            self.name
        )

    @abstractmethod
    def is_branch(self):
        return self.children is not None

    @abstractmethod
    def is_leaf(self):
        return self.children is None

    @abstractmethod
    def data(self):
        pass


class ResourceHelper(object):
    __metaclass__ = ABCMeta

    def __init__(self, root=None, acls=None, tags=None, logger=None,
                 enable_access_log=True, enable_operation_log=False):
        if root is None:
            root = Resource(name='', rid='ROOT',
                            owner=constants.SECURITY_IDENTITY_ROLE_PREFIX + constants.ROLE_NAME_ADMIN,
                            group=constants.SECURITY_IDENTITY_ROLE_PREFIX + constants.ROLE_NAME_LOGIN_USER,
                            mode=0b111100000, children=[], ctime=0, mtime=0, atime=0, links=[], blocks=[],
                            helper=self)
        self.root = root
        self.acls = acls
        self.tags = tags
        self.logger = logger
        self.enable_access_log = enable_access_log
        self.enable_operation_log = enable_operation_log

    @abstractmethod
    def query_of_user(self, user=None):
        pass

    @abstractmethod
    def query(self, dsl):
        pass

    @property
    def is_acl_support(self):
        return self.acls is not None

    def load_acls(self, resource):
        if self.is_acl_support:
            self.acls.load(resource)
        pass

    def add_acls(self, resource, aces, user=None):
        if self.is_acl_support:
            self.acls.add(resource, aces, user=user)
        else:
            pass

    def remove_acls(self, resource, sids, user=None):
        if self.is_acl_support:
            self.acls.add(resource, sids, user=user)
        else:
            pass

    def clear_acls(self, resource, user=None):
        if self.is_acl_support:
            self.acls.clear(resource, user=user)
        else:
            pass

    @property
    def is_xattr_support(self):
        return False

    @abstractmethod
    def load_xattrs(self, resource):
        pass

    @abstractmethod
    def update_xattrs(self, resource, xattrs):
        pass

    @abstractmethod
    def remove_xattrs(self, resource, keys):
        pass

    @abstractmethod
    def clear_xattrs(self, resource):
        pass

    @property
    def is_tag_support(self):
        return self.acls is not None

    def load_tags(self, resource):
        if self.is_tag_support:
            return self.tags.load(resource)
        pass

    def add_tags(self, resource, tags, user=None):
        if self.is_tag_support:
            self.tags.add(resource, tags, user=user)
        else:
            pass

    def remove_tags(self, resource, tags, user=None):
        if self.is_tag_support:
            self.tags.remove(resource, tags, user=user)
        else:
            pass

    def clear_tags(self, resource, user=None):
        if self.is_tag_support:
            self.tags.clear(resource, user=user)
        else:
            pass

    @property
    def is_log_support(self):
        return self.logger is not None

    def log(self, resource, event=None, user=None, **kwargs):
        if self.is_log_support:
            self.logger.log(resource, event=event, user=user, **kwargs)

    @abstractmethod
    def instance(self, parent=None, name=None, **kwargs):
        pass

    @abstractmethod
    def create(self, resource, user=None, **kwargs):
        pass

    @abstractmethod
    def find_by_path(self, path, **kwargs):
        pass

    @abstractmethod
    def find_by_id(self, rid, **kwargs):
        pass

    def find_one(self, path=None, rid=None, **kwargs):
        if path is not None:
            return self.find_by_path(path=path, **kwargs)
        if rid is not None:
            return self.find_by_path(rid=rid, **kwargs)

    @abstractmethod
    def find_all(self, query, **kwargs):
        pass

    @abstractmethod
    def count(self, query, **kwargs):
        pass

    def exists(self, path=None, rid=None, **kwargs):
        return self.find_one(path=path, rid=rid, **kwargs) is not None

    @abstractmethod
    def update(self, resource, user=None, **kwargs):
        pass

    @abstractmethod
    def delete(self, path, user=None, **kwargs):
        pass


    def save(self, resource, **kwargs):
        pass
