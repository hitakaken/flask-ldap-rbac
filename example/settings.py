# -*- coding: utf-8 -*-
LDAP = {
    'BASE_DN': 'dc=maxcrc,dc=com',
    'ROOT_DN': 'cn=Manager,dc=maxcrc,dc=com',
    'ROOT_PW': 'secret',
    'URI': 'ldap://127.0.0.1',
    'OPTIONS':{
        'REQUIRE_CERT': True,
        'CACERTFILE': 'D:/Tools/ldap/OpenLDAP/secure/certs/server.pem',
        'DEBUG_LEVEL': 0
    },
    'START_TLS': True,
    'TRACE_LEVEL': 1
}

TOKEN = {
    'SECRET': 'base',
    'EXPIRED': 5000
}
JWT = {
    'secret': 'secret',
    'algorithm': 'HS256'
}
RESTPLUS_MASK_SWAGGER = False
