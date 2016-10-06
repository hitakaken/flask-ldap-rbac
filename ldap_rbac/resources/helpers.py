# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod
from ldap_rbac.core import constants
from models import Resource


class ResourceHelper(object):
    __metaclass__ = ABCMeta

    def __init__(self, root=None, acls=None, tags=None, logger=None,
                 enable_access_log=True, enable_operation_log=False):
        if root is None:
            root = Resource(name='', rid='ROOT',
                            owner=constants.SECURITY_IDENTITY_ROLE_PREFIX + constants.ROLE_NAME_ADMIN,
                            group=constants.SECURITY_IDENTITY_ROLE_PREFIX + constants.ROLE_NAME_LOGIN_USER,
                            mode=0o740, children=[], ctime=0, mtime=0, atime=0, links=[], blocks=[],
                            helper=self)
        self.root = root
        self.root.loaded = True
        self.acls = acls
        self.tags = tags
        self.logger = logger
        self.enable_access_log = enable_access_log
        self.enable_operation_log = enable_operation_log

    @property
    def type(self):
        return 'Base'

    @abstractmethod
    def query_of_user(self, user=None):
        pass

    @abstractmethod
    def query(self, dsl):
        pass

    @property
    def is_acl_support(self):
        return self.acls is not None

    @property
    def is_acl_together(self):
        return False

    def load_acls(self, resource):
        if self.is_acl_support:
            self.acls.load(resource)

    @property
    def is_xattr_support(self):
        return False

    @abstractmethod
    def load_xattrs(self, resource):
        pass

    @property
    def is_tag_support(self):
        return self.acls is not None

    @property
    def is_tag_together(self):
        return False

    def load_tags(self, resource):
        if self.is_tag_support:
            return self.tags.load(resource)

    @property
    def is_log_support(self):
        return self.logger is not None

    def log(self, resource, event=None, user=None, **kwargs):
        if self.is_log_support:
            self.logger.log(resource, event=event, user=user, **kwargs)

    def rel_path(self, path):
        return path[len(self.root.path):]

    def instance_by_path(self, path, underlying=None):
        if not path.startswith(self.root.path):
            return None
        rel_path = self.rel_path(path)
        if len(rel_path) == 0:
            return self.root
        names = rel_path.split('/')
        current = self.root
        for idx in range(0, len(names)):
            current = Resource(parent=current, name=names[idx], helper=self, underlying=underlying)
        return current

    def instance(self, parent=None, name=None, underlying=None, **kwargs):
        parent = self.root if parent is None else parent
        return Resource(parent=parent, name=name, helper=self, underlying=underlying, **kwargs)

    @abstractmethod
    def create(self, resource, user=None, **kwargs):
        pass

    @abstractmethod
    def find_by_path(self, path, **kwargs):
        if path == self.root.path:
            return self.root
        return None

    @abstractmethod
    def find_by_id(self, rid, **kwargs):
        if rid == self.root.rid:
            return self.root
        return None

    def find_one(self, path=None, rid=None, **kwargs):
        if path is not None:
            return self.find_by_path(path=path, **kwargs)
        if rid is not None:
            return self.find_by_id(rid=rid, **kwargs)

    @abstractmethod
    def find_all(self, query, **kwargs):
        pass

    @abstractmethod
    def count(self, query, **kwargs):
        pass

    def exists(self, path=None, rid=None, **kwargs):
        return self.find_one(path=path, rid=rid, **kwargs) is not None

    @abstractmethod
    def list(self, resource):
        pass

    @abstractmethod
    def update(self, resource, user=None, **kwargs):
        pass

    @abstractmethod
    def delete(self, path, user=None, **kwargs):
        pass

    @abstractmethod
    def read(self, resource):
        pass

    @abstractmethod
    def write(self, resource):
        pass

    @abstractmethod
    def append(self, resource):
        pass
