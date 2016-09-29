# -*- coding: utf-8 -*-
from tinydb import TinyDB, Query
from ldap_rbac.models import TokenUser
from ldap_rbac.resources import TinyDbResources
import settings

user = TokenUser(name='kcao', uid='6ea51701-8580-11e6-94a3-615c6c263909', roles=['Admin'])

print user.is_admin

db = TinyDB(settings.RESOURCE_SOURCE)

resources = TinyDbResources(db=db)

bills = resources.instance(name='bills')

print resources.exists(path=bills.path, user=user)


