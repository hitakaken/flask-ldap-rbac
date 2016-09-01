



class Token(object):
    def __init__(self):
        pass




# Schema Name, Schema DN, Schema Description, objectClasses
schemas = [
    ('Config', 'ou=Config', 'Fortress People',
     'cn', ['device', 'ftProperties']),
    ('User', 'ou=People', 'Fortress People',
     'cn', ['top', 'inetOrgPerson', 'ftUserAttrs', 'ftProperties', 'ftMods', 'extensibleObject']),
    ('Policy', 'ou=Policies', 'Fortress Policies',
     'cn', ['top', 'device', 'pwdPolicy', 'ftMods']),
    ('RBAC', 'ou=RBAC', 'Fortress RBAC Policies',
     'ou', ['organizationalUnit']),
    ('Role', 'ou=Roles,ou=RBAC', 'Fortress Roles',
     'cn', ['top', 'ftRls', 'ftProperties', 'ftMods']),
    ('Permission', 'ou=Permissions,ou=RBAC', 'Fortress Permissions',
     ['ftObjNm', 'ftOpNm'], ['top', 'organizationalUnit', 'ftObject', 'ftProperties', 'ftMods'],
     ['top', 'organizationalRole', 'ftOperation', 'ftProperties', 'ftMods']
     ),
    ('Constraint', 'ou=Constraints,ou=RBAC', 'Fortress Separation of Duty Constraints',
     'cn', ['top', 'ftSSDSet', 'ftMods']),
    ('ARBAC', 'ou=ARBAC', 'Fortress Administrative RBAC Policies',
     'ou', ['organizationalUnit']),
    ('OS-U', 'ou=OS-U,ou=ARBAC', 'Fortress User Organizational Units',
     'ou', ['top', 'ftOrgUnit', 'ftMods']),
    ('OS-P', 'ou=OS-P,ou=ARBAC', 'Fortress Perm Organizational Units',
     'ou', ['top', 'ftOrgUnit', 'ftMods']),
    ('AdminRole', 'ou=AdminRoles,ou=ARBAC', 'Fortress AdminRoles',
     'cn', ['top', 'ftRls', 'ftProperties', 'ftPools', 'ftMods']),
    ('AdminPerm', 'ou=AdminPerms,ou=ARBAC', 'Admin Permissions',
     ['ftObjNm', 'ftOpNm'], ['top', 'organizationalUnit', 'ftObject', 'ftProperties', 'ftMods'],
     ['top', 'organizationalRole', 'ftOperation', 'ftProperties', 'ftMods'])
]


def initialize(ldap_connection):
    # 初始化表
    # https://github.com/apache/directory-fortress-core/blob/master/src/test/resources/init-ldap.ldif
    # NOTICE: BASE_DN 必须存在
    global schemas
    for schema in schemas:
        (name, prefix, description) = schema
        dn = '%s,%s' % (prefix, GLOBAL_BASE_DN)
        try:
            ldap_connection.search_s(dn, ldap.SCOPE_BASE, '(objectClass=*)')
        except ldap.NO_SUCH_OBJECT:
            modlist = [  # ldap.modlist.addModlist({
                ('objectClass', 'organizationalUnit'),
                ('ou', convert_dn_to_list(prefix)[0][1]),
                ('description', description)
            ]  # })
            print dn, modlist
            ldap_connection.add_s(dn, modlist)



