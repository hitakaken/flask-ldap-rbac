# -*- coding: utf-8 -*-
import ldap
from ldap_login.models import context, users
import settings

context.initialize(settings.LDAP)
# users.add_user({'uid': 'kcao', 'cn': 'Cao Ke',
#                 'emails': ['kcao@libnet.sh.cn', 'hitakaken@gmail.com'], 'mobiles': ['13651649647']})

# user = users.find({'ftId': 'b370de80-7416-11e6-b3d5-811ad2761c64'})
user = users.read({'uid': 'kcao'})
id = user.id[0]
user = {
    'ftId': id,
    'sn': '曹可',
    'emails': 'kcao@libnet.sh.cn'
}
users.update(user)
user = users.read({'uid': 'kcao'})
# users.authenticate('kcao', 'kenshin77')
users.passwd({'ftId': id}, 'kenshin777', 'kenshin77')
users.passwd({'ftId': id}, None, 'kenshin777', check=False)
users.authenticate({'sn': 'kcao'}, 'kenshin77')
user = users.read({'ftId': id})
user.phones = ['64455555-8427']
users.update(user)
print user.attrs
