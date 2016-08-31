# -*- coding: utf-8 -*-
class Entity(object):
    objectclass = ['ftMods']

    def __init__(self):
        pass


class UserMixin(object):
    objectclass = ['inetOrgPerson', 'organizationalPerson', 'ftProperties', 'ftUserAttrs', 'ftMods']

    def __init__(self):
        pass


class OrgUnit(object):
    objectclass = ['organizationalUnit', 'ftOrgUnit', 'ftMods']

    def __init__(self):
        pass


class Administrator(object):
    def __init__(self):
        pass


class RoleMixin(object):
    objectclass = ['organizationalRole', 'ftRls', 'ftProperties', 'ftMods']
    roles = {}

    def __init__(self):
        pass


class UserRole(object):
    objectclass = ['ftUserAttrs']

    def __init__(self):
        pass


class PermissionMixin(object):
    objectclass = ['ftOperation', 'ftProperties', 'ftMods']

    def __init__(self):
        pass


class PermissionObjectMixin(object):
    objectclass = ['ftObject', 'ftProperties', 'ftMods']

    def __init__(self):
        pass


class Token(object):
    def __init__(self):
        pass
