# -*- coding: utf-8 -*-
from flask_login import UserMixin


class TokenUser(UserMixin):
    def __init__(self, name=None, uid=None):
        self.name = name
        self.uid = uid

    @staticmethod
    def wrap(user):
        return TokenUser(
            name=user.uid,
            uid=user.id,
            roles=user.roles
        )

