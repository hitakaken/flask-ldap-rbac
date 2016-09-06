# -*- coding: utf-8 -*-
import ldap
from ldap_login.models import context, users
import settings

context.initialize(settings.LDAP)
# users.add_user({'uid': 'kcao', 'cn': 'Cao Ke',
#                 'emails': ['kcao@libnet.sh.cn', 'hitakaken@gmail.com'], 'mobiles': ['13651649647']})

# user = users.find({'ftId': 'b370de80-7416-11e6-b3d5-811ad2761c64'})
user = users.read({'ftId': 'dca76401-7442-11e6-94a3-6165a020b7a2'})
user.cn = '曹可'
user = {
    'ftId': 'dca76401-7442-11e6-94a3-6165a020b7a2',
    'emails': 'kcao@libnet.sh.cn'
}
users.update(user)
user = users.read({'uid': 'kcao'})
print user.attrs
