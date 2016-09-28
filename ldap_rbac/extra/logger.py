# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod


class ResourceLogger(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def log(self, resource, event=None, user=None, **kwargs):
        pass
