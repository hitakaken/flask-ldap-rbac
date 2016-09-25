# -*- coding: utf-8 -*-
from ldap_rbac.models import Config, User
from ldap_rbac.helpers import LdapConnection, ConfigHelper, UserHelper
import settings
# LDAP 定义
connection = LdapConnection(ldap_config=settings.LDAP)
connection.begin()
# DAO 定义
configs = ConfigHelper(connection, name='configs')
users = UserHelper(connection, name='users')
# 初始化
connection.initialize()
