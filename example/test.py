# -*- coding: utf-8 -*-
import ldap
from ldap_login.models import context, users
import settings

context.initialize(settings.LDAP)
# users.add_user({
#     'uid': 'kcao',
#     'cn': 'Cao Ke',
#     'mail': ['kcao@libnet.sh.cn', 'hitakaken@gmail.com'],
#     'mobile': ['13651649647']
# })

user = users.find({'uid': 'kcao'})
print user.attrs
