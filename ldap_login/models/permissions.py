# -*- coding: utf-8 -*-
from .base import FortEntityWithProperties


class PermObj(FortEntityWithProperties):
    object_class = ['top', 'organizationalUnit', 'ftObject', 'ftProperties', 'ftMods']
    idx_field = 'ftObjNm'
    branch_part = 'ou=Permissions,ou=RBAC'
    branch_description = 'Fortress Permissions'

    def __init__(self, dn=None, attrs=None):
        super(PermObj, self).__init__(dn=dn, attrs=attrs)


class Permission(FortEntityWithProperties):
    object_class = ['top', 'organizationalRole', 'ftOperation', 'ftProperties', 'ftMods']
    idx_field = 'ftOpNm'

    def __init__(self, dn=None, attrs=None):
        if attrs is None:
            attrs = {}
        if 'ftObjNm' in attrs:
            self.branch_part = 'ftObjNm=%s,ou=Permissions,ou=RBAC' % attrs['ftObjNm']
        elif dn is not None and ',' in dn:
            self.branch_part = dn.split(',')[1] + ',ou=Permissions,ou=RBAC'
        super(Permission, self).__init__(dn=dn, attrs=attrs)
