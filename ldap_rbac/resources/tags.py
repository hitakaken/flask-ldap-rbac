# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod
from ldap_rbac.core import exceptions
import six


class Tags(object):
    def __init__(self, resource, tags=None):
        self.resource = resource
        if tags is None:
            tags = {}
        self.tags = tags

    def clear(self, user=None):
        if self.resource.is_admin(user=user) or self.resource.has_owner(user=user):
            self.tags = {}
        else:
            raise exceptions.EPERM

    def list_all(self, user=None):
        if not self.resource.can_read(user=user):
            raise exceptions.EPERM
        return self.tags

    def list(self, user=None):
        if not self.resource.can_read(user=user):
            raise exceptions.EPERM
        return [k for k, v in six.iteritems(self.tags) if user.id in v]

    def has(self, tag, user=None):
        if not self.resource.can_read(user=user):
            raise exceptions.EPERM
        return tag in self.tags and user.id in self.tags.get(tag, [])

    def tag(self, tag, user=None):
        if not self.resource.can_tags(user=user):
            raise exceptions.EPERM
        if tag not in self.tags:
            self.tags[tag] = []
        if user.id not in self.tags[tag]:
            self.tags[tag].append(user.id)

    def untag(self, tag, user=None):
        if not self.resource.can_tags(user=user):
            raise exceptions.EPERM
        if tag in self.tags and user.id in self.tags.get(tag, []):
            self.tags[tag].remove(user.id)
        if tag in self.tags and len(self.tags[tag]) == 0:
            self.tags.pop(tag, None)


class TagsHelper(object):
    __metaclass__ = ABCMeta

    @property
    def type(self):
        return 'Base'

    @abstractmethod
    def load(self, resource, force=False):
        pass

    @abstractmethod
    def save(self, resource):
        pass

