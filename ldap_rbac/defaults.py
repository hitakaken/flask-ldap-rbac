# -*- coding: utf-8 -*-
import datetime

JWT_SECRET = 'secret'
JWT_ALGORITHM =  'HS256'
JWT_EXPIRED_TIMEDELTA = datetime.timedelta(hours=8)
JWT_LEEWAY = datetime.timedelta(minutes=10)