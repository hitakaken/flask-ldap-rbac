# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod, abstractproperty


class Resource(object):
    __metaclass__ = ABCMeta
    permissions = []

    def __init__(self, parent, name, helper=None, loaded=False):
        self.parent = parent
        self.name = name
        self.helper = helper
        self.loaded = False

    def can_read(self):
        pass

    def can_write(self):
        pass

    def can_control(self):
        pass

    @abstractmethod
    def create(self):
        pass

    @abstractmethod
    def delete(self):
        pass

    @abstractmethod
    def exists(self):
        pass

    @abstractmethod
    def get_name(self):
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

    @abstractproperty
    def is_acl_support(self):
        return False

    @abstractproperty
    def is_log_support(self):
        return False

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

    def save(self, resource, user=None, **kwargs):
        pass