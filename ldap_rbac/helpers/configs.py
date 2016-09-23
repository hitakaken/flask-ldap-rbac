# -*- coding: utf-8 -*-
from ldap_rbac.models import Config
from ldap_rbac.core.helpers import BaseHelper


class ConfigHelper(BaseHelper):
    """配置集合"""
    def __init__(self, ldap_connection):
        super(ConfigHelper,self).__init__(ldap_connection)

    def entity_class(self):
        return Config