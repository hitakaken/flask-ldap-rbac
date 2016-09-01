slapd.conf

```
include		./schema/fortress.schema
include		./schema/rbac.schema

index uidNumber pres
index gidNumber pres
index ftObjNm
index ftOpNm
index ftRoleName
index uid
index ou eq,sub
index ftId
index ftPermName
index ftRoles
index ftUsers
index ftRA
index ftARA eq
```