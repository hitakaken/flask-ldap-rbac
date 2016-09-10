# -*- coding: utf-8 -*-
import ldap
from ldap_rbac.models import context, users
import settings
from ldap_rbac.ldaphelper import make_secret

print make_secret('secret')


