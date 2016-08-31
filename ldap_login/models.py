# -*- coding: utf-8 -*-
import ldap
import ldap.schema


class Entity(object):
    objectclass = ['ftMods']

    def __init__(self, objectclass=None):
        if objectclass is None:
            objectclass = []
        self.objectclass = Entity.objectclass.append(objectclass)

    def add(self, l):
        l.add_s(self)


class User(Entity):
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


def initialize(uri):
    subschemasubentry_dn, schema = ldap.schema.urlfetch(uri)
    ftMods = schema.get_obj(ldap.schema.ObjectClass, 'ftProperties')
    if not ftMods is None:
        print ftMods.must, ftMods.may


initialize('ldap://127.0.0.1')
