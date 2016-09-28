# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod


class Tag(object):
    def __init__(self, name=None, sid=None, ctime=None):
        self.name = name
        self.sid = sid
        self.ctime = ctime


class TagsHelper(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def load(self, resource, force=False):
        pass

    @abstractmethod
    def add(self, resource, tags, user=None):
        pass

    @abstractmethod
    def remove(self, resource, tags, user=None):
        pass

    @abstractmethod
    def clear(self, resource):
        pass

    @abstractmethod
    def save(self, resource):
        pass
