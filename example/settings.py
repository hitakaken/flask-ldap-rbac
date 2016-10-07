# -*- coding: utf-8 -*-
from ldap_rbac.core import constants

LDAP = {
    'BASE_DN': 'dc=novbase,dc=com',
    'ROOT_DN': 'cn=Manager,dc=novbase,dc=com',
    'ROOT_PW': 'xxzx123-456',
    'URI': 'ldap://127.0.0.1',
    'OPTIONS': {
        'REQUIRE_CERT': True,
        'CACERTFILE': 'D:/Tools/ldap/OpenLDAP/secure/certs/server.pem',
        'DEBUG_LEVEL': 0
    },
    'START_TLS': True,
    'TRACE_LEVEL': 1
}
TOKEN = {
    'HEADER': 'AUTH',
    'SECRET': 'core',
    'EXPIRED': 5000
}
JWT = {
    'secret': 'secret',
    'algorithm': 'HS256'
}
BUILT_IN_RBAC = {
    'USERS': [
        {'uid': 'admin'}
    ],
    'ROLES': [
        {'name': constants.ROLE_NAME_ADMIN},
        {'name': constants.ROLE_NAME_MANAGER},
        {'name': constants.ROLE_NAME_LOGIN_USER}
    ]
}
RESTPLUS_HOST = "127.0.0.1:5000"
RESTPLUS_MASK_SWAGGER = False
RESOURCE_SOURCE_TYPE = 'tinydb'
RESOURCE_SOURCE = 'D:/Workspace/data/yiren/bills.json'
LOGGER_TYPE = 'tinydb'
LOGGER_SOURCE = 'D:/Workspace/data/yiren/logs.json'
