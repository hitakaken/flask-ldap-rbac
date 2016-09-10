# -*- coding: utf-8 -*-
from bidict import bidict
import ldap
from ldap_rbac import exceptions
from ldap_rbac.models.base import FortEntityWithProperties
from ldap_rbac.models.helper import GLOBAL_LDAP_CONNECTION


class User(FortEntityWithProperties):
    object_class = ['top',
                    'inetOrgPerson', 'organizationalPerson',
                    'ftUserAttrs', 'ftProperties', 'ftMods', 'extensibleObject']
    idx_field = 'uid'
    branch_part = 'ou=People'
    branch_description = 'Fortress People'
    id_attr_names = ['ftId', 'sn']
    mapping = bidict(
        name='cn',
        displayname='display',
        mail='emails',
        mobile='mobiles',
        telephoneNumber='phones'
    )

    def __init__(self, dn=None, attrs=None):
        super(User, self).__init__(dn=dn, attrs=attrs)

UserSchema = {
    'type': 'object',
    'properties': {
        'name': {
            'type': 'string'
        }
    }
}


def create(user):
    if isinstance(user, dict):
        user = User(attrs=user)
    if 'sn' not in user.attrs:
        user.attrs['sn'] = user.idx_value
    cached_user = GLOBAL_LDAP_CONNECTION.find(user)
    if cached_user is not None:
        raise exceptions.UserAlreadyExists()
    GLOBAL_LDAP_CONNECTION.add_entry(user)


def read(user):
    if isinstance(user, dict):
        user = User(attrs=user)
    user = GLOBAL_LDAP_CONNECTION.find(user)
    return user


def update(user):
    if isinstance(user, dict):
        user = User(attrs=user)
    cached_user = GLOBAL_LDAP_CONNECTION.find(user)
    if cached_user is None:
        raise exceptions.UserNotFound()
    result = GLOBAL_LDAP_CONNECTION.save_entry(cached_user.update(user.attrs))
    return result


def delete(user):
    user = read(user)
    # TODO


def check_passwd(user, password):
    try:
        GLOBAL_LDAP_CONNECTION.auth_conn.simple_bind_s(user.dn, password)
        return True
    except ldap.INVALID_CREDENTIALS:
        return False


def passwd(user, oldpw, newpw, check=True):
    user = read(user)
    if check and 'userpassword' in user.attrs:
        if oldpw is None or not check_passwd(user, oldpw):
            raise exceptions.InvalidCredentials()
    if not check or 'userpassword' not in user.attrs:
        oldpw = None
    GLOBAL_LDAP_CONNECTION.conn.passwd_s(user.dn, oldpw, newpw)


def authenticate(user, password):
    user = read(user)
    if user is None:
        raise exceptions.UserNotFound()
    if not check_passwd(user, password):
        raise exceptions.InvalidCredentials()
    return user
