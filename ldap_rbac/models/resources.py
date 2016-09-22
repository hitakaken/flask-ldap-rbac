# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod


class Resource(object):
    __metaclass__ = ABCMeta
    permissions = []

    def get_permissions(self):
        return self.permissions

    def add_permission(self, permission):
        self.permissions.append(permission)

    @abstractmethod
    def grant(self, who, permissions):
        pass

    @abstractmethod
    def revoke(self, who, permissions):
        pass

    @abstractmethod
    def revoke_all(self, who):
        pass

    @abstractmethod
    def check(self, who, permission):
        return False

    @abstractmethod
    def check_any(self, who, permissions):
        return False

    @abstractmethod
    def check_all(self, who, permissions):
        return False

    @abstractmethod
    def which(self, who):
        pass

    @abstractmethod
    def show(self):
        pass

    @abstractmethod
    def save(self):
        pass





