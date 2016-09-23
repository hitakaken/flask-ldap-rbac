# -*- coding: utf-8 -*-
from ldap_rbac.models import Config, User
from ldap_rbac.helpers import LdapConnection, ConfigHelper
import settings

entity_classes = [Config, User]
connection = LdapConnection(ldap_config=settings.LDAP)
connection.begin()
connection.load_entity_classes(entity_classes)
connection.register_entity_classes(entity_classes)

configs = ConfigHelper(connection)

