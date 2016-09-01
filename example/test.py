# -*- coding: utf-8 -*-
import ldap
from ldap_login.models import User
from ldap_login import models
import settings

CACERTFILE = 'D:/Tools/ldap/OpenLDAP/secure/certs/server.pem'

ldap.set_option(ldap.OPT_DEBUG_LEVEL, 0)
ldapmodule_trace_level = 1
# ldapmodule_trace_file = sys.stderr

ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, CACERTFILE)


conn = ldap.initialize(settings.LDAP['URI'], trace_level=ldapmodule_trace_level)
conn.protocol_version=ldap.VERSION3
conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
conn.start_tls_s()
conn.simple_bind_s(settings.LDAP['ROOT_DN'], settings.LDAP['ROOT_PW'])

models.initialize(conn)

conn.unbind_s()
