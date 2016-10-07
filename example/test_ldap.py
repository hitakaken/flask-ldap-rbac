# -*- coding: utf-8 -*-
from ldap_rbac.core import constants
from ldap_rbac.models import Config, User, UserRole
from ldap_rbac.helpers import LdapConnection, ConfigHelper, UserHelper, RoleHelper
import settings
# LDAP 定义
connection = LdapConnection(ldap_config=settings.LDAP)
connection.begin()
# DAO 定义
configs = ConfigHelper(connection, name='configs')
users = UserHelper(connection, name='users')
roles = RoleHelper(connection, name='roles')
# 初始化
connection.initialize()

kcao = users.instance(attrs={
    'uid': 'longli',
    'sn': ['longli']
})

users.save(kcao)

admin = roles.instance(dn=constants.ROLE_NAME_ADMIN)
admin = roles.save(admin)
login_user = roles.instance(dn=constants.ROLE_NAME_LOGIN_USER)
login_user = roles.save(login_user)

users.change_password('longli', None, 'longli')

users.assign(UserRole(user=kcao, role=admin))
users.assign(UserRole(user=kcao, role=login_user))
users.deassign(UserRole(user=kcao, role=login_user))

users.save(kcao)

print users.check_password(kcao, 'kenshin77')
