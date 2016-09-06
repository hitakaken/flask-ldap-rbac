# -*- coding: utf-8 -*-
# http://csrc.nist.gov/groups/SNS/rbac/documents/draft-rbac-implementation-std-v01.pdf
# http://schd.ws/hosted_files/apachecon2016/f1/How%20I%20Built%20an%20IAM%20System%20using%20Java%20and%20Apache%20Directory%20Fortress.pdf

from .base import FortEntity
from .helper import GLOBAL_LDAP_CONNECTION


class Policy(FortEntity):
    object_class = ['top', 'device', 'pwdPolicy', 'ftMods']
    idx_field = 'cn'
    branch_part = 'ou=Policies'
    branch_description = 'Fortress Policies'

    def __init__(self, dn=None, attrs=None):
        super(Policy, self).__init__(dn=dn, attrs=attrs)


class RBAC(FortEntity):
    object_class = ['organizationalUnit']
    idx_field = 'ou'
    branch_part = 'ou=RBAC'
    branch_description = 'Fortress RBAC Policies'

    def __init__(self, dn=None, attrs=None):
        super(RBAC, self).__init__(dn=dn, attrs=attrs)


class Constraint(FortEntity):
    object_class = ['top', 'ftSSDSet', 'ftMods']
    idx_field = 'cn'
    branch_part = 'ou=Constraints,ou=RBAC'
    branch_description = 'Fortress Separation of Duty Constraints'

    def __init__(self, dn=None, attrs=None):
        super(Constraint, self).__init__(dn=dn, attrs=attrs)

