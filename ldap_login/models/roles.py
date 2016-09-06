# -*- coding: utf-8 -*-
from .base import FortEntityWithProperties


class Role(FortEntityWithProperties):
    object_class = ['top', 'ftRls', 'ftProperties', 'ftMods']
    idx_field = 'cn'
    branch_part = 'ou=Roles,ou=RBAC'
    branch_description = 'Fortress Roles'

    def __init__(self, dn=None, attrs=None):
        super(Role, self).__init__(dn=dn, attrs=attrs)
