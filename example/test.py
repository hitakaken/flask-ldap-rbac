# -*- coding: utf-8 -*-
import ldap
from ldap_login.models import context, users
import settings
from ldap_login.ldaphelper import make_secret

print make_secret('secret')


