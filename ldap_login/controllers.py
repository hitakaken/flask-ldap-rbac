# -*- coding: utf-8 -*-
from flask import Blueprint

mod_ldap_login = Blueprint('ldap_login', __name__)

ldap_manager = None
