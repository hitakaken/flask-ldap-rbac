# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod


class Tag(object):
    def __init__(self, name=None, sid=None, ctime=None):
        self.name = name
        self.sid = sid
        self.ctime = ctime

    def __str__(self):
        return '%s$%s$%s' % (
            self.name,
            self.sid if self.sid is not None else '',
            str(self.ctime)
        )


def tag_of(text, splitter='$'):
    name, sid, ctime = text.split(splitter)
    return Tag(name=name, sid=sid, ctime=int(ctime))


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
