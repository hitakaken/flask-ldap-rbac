import ldap, ldap.schema
import urllib
import ldif
import os
from ldif import LDIFParser, LDIFWriter, LDIFRecordList
from ldap_login.driver import get_schema
from ldap_login.driver import LdapDriver
from ldap_login import ldaphelper

import settings

parser = LDIFRecordList(open('../ldap_login/schema/apacheds-fortress.ldif', 'rb'))
parser.parse()

print parser.all_records

for dn, entry in parser.all_records:
    print dn, entry

# driver = LdapDriver(config=settings.LDAP)
# driver.connect()
# l = driver.conn
# bind_dn = driver.config['BIND_DN']
# bind_auth = driver.config['BIND_AUTH']
# print bind_dn, bind_auth
# l.simple_bind_s(bind_dn, bind_auth)

# result = l.search_s('cn=subschema', ldap.SCOPE_BASE, '(objectclass=*)', ['*','+'])
# subschema_entry = ldaphelper.get_search_results(result)[0]
# subschema_subentry = subschema_entry.get_attributes()
# print subschema_subentry



# l.unbind_s()

