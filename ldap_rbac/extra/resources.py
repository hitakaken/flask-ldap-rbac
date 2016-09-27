# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod, abstractproperty


class ResourceInfo(object):
    def __init__(self, name=None, owner=None, group=None, mode=None,
                 ctime=None, mtime=None, atime=None):
        self.name = name
        self.owner = owner
        self.group = group
        self.mode = mode
        self.ctime = ctime
        self.mtime = mtime
        self.atime = atime


class Resource(object):
    __metaclass__ = ABCMeta

    def __init__(self, parent, name, helper=None):
        self.parent = parent
        self.name = name
        self.helper = helper
        self.loaded_info = None
        self.loaded_acls = None
        self.loaded_xattrs = None
        self.loaded_tags = None

    @property
    def info(self, force=False):
        if self.loaded_info is None or force:
            self.loaded_info = self.helper.load_info(self)
        return self.loaded_info

    @property
    def acls(self, force=False):
        if self.loaded_acls is None or force:
            self.loaded_acls = self.helper.load_acls(self)
        return self.loaded_acls

    @property
    def xattrs(self, force=False):
        if self.loaded_xattrs is None or force:
            self.loaded_xattrs = self.helper.load_xattrs(self)
        return self.loaded_xattrs

    @property
    def tags(self, force=False):
        if self.loaded_tags is None or force:
            self.loaded_tags = self.helper.load_tags(self)
        return self.loaded_tags

    def can_read(self):
        pass

    def can_write(self):
        pass

    def can_control(self):
        pass

    @abstractmethod
    def get_path(self):
        pass

    @abstractmethod
    def get_parent(self):
        pass

    @abstractmethod
    def is_directory(self):
        pass

    @abstractmethod
    def is_file(self):
        pass

    @abstractmethod
    def list(self):
        pass

    @abstractmethod
    def mkdir(self):
        pass

    @abstractmethod
    def last_modify(self):
        pass

    @abstractmethod
    def data(self):
        pass

    @abstractmethod
    def save(self):
        pass


class ResourceHelper(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def load_info(self, resource):
        pass

    @staticmethod
    def is_acl_support():
        return False

    @abstractmethod
    def load_acls(self, resource):
        pass

    @abstractmethod
    def add_acls(self, resource, aces):
        pass

    @abstractmethod
    def remove_acls(self, resource, sids):
        pass

    @abstractmethod
    def clear_acls(self, resource):
        pass

    @staticmethod
    def is_xattr_support():
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

    @staticmethod
    def is_tag_support():
        return False

    @abstractmethod
    def load_tags(self, resource):
        pass

    @abstractmethod
    def add_tags(self, resource, tags):
        pass

    @abstractmethod
    def remove_tags(self, resource, tags):
        pass

    @abstractmethod
    def clear_tags(self, resource):
        pass

    @staticmethod
    def is_log_support(self):
        return False

    @abstractmethod
    def log(self, resource, event):
        pass

    @abstractmethod
    def instance(self, parent=None, name=None, user=None, **kwargs):
        pass

    @abstractmethod
    def create(self, resource, user=None, **kwargs):
        pass

    @abstractmethod
    def find_one(self, path, user=None, **kwargs):
        pass

    @abstractmethod
    def find_all(self, query, user=None, **kwargs):
        pass

    @abstractmethod
    def count(self, query):
        pass

    @abstractmethod
    def exists(self, path, user=None, **kwargs):
        pass

    @abstractmethod
    def update(self, resource, user=None, **kwargs):
        pass

    @abstractmethod
    def delete(self, path, user=None, **kwargs):
        pass

    @abstractmethod
    def log(self, resource, user=None, **kwargs):
        pass

    def save(self, resource, **kwargs):
        pass
