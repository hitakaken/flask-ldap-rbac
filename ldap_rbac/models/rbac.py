# -*- coding: utf-8 -*-
# http://csrc.nist.gov/groups/SNS/rbac/documents/draft-rbac-implementation-std-v01.pdf
# http://schd.ws/hosted_files/apachecon2016/f1/How%20I%20Built%20an%20IAM%20System%20using%20Java%20and%20Apache%20Directory%20Fortress.pdf
from ldap_rbac.core import utils
from ldap_rbac.core.models import LdapEntity, PropertiesEntity, Constraint


class User(PropertiesEntity):
    """Fortress People"""
    ID_FIELD = 'uid'
    ROOT = 'ou=People'
    OBJECT_CLASS = ['top', 'inetOrgPerson', 'organizationalPerson',
                    'ftUserAttrs', 'ftProperties', 'ftMods', 'extensibleObject']

    def __init__(self, dn=None, attrs=None):
        super(User, self).__init__(dn=dn, attrs=attrs)


class Role(PropertiesEntity):
    """Fortress Roles"""
    ID_FIELD = 'cn'
    ROOT = 'ou=Roles,ou=RBAC'
    OBJECT_CLASS = ['top', 'ftRls', 'ftProperties', 'ftMods']

    def __init__(self, dn=None, attrs=None):
        super(Role, self).__init__(dn=dn, attrs=attrs)


class UserRole(Constraint):
    def __init__(self, name=None, timeout=None, begin_time=None, end_time=None, begin_date=None,
                 end_date=None, day_mask=None, begin_lock_date=None, end_lock_date=None,
                 raw_data=None, **kwargs):
        if raw_data is not None:
            super(UserRole, self).__init__(name=name, timeout=timeout, begin_time=begin_time, end_time=end_time,
                                           begin_date=begin_date, end_date=end_date, day_mask=day_mask,
                                           begin_lock_date=begin_lock_date, end_lock_date=end_lock_date, **kwargs)
        else:
            self.parse(raw_data)

    def raw_data(self):
        return super(UserRole, self).raw_data()


class PWPolicy(LdapEntity):
    """Fortress Policies"""
    ID_FIELD = 'cn'
    ROOT = 'ou=Policies'
    OBJECT_CLASS = ['top', 'device', 'pwdPolicy', 'ftMods']

    def __init__(self, dn=None, attrs=None):
        super(PWPolicy, self).__init__(dn=dn, attrs=attrs)