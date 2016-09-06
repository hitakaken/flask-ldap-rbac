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

user = users.find({'ftId': 'b370de80-7416-11e6-b3d5-811ad2761c64'})
print user.attrs
