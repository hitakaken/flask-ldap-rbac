# -*- coding: utf-8 -*-
from abc import ABCMeta, abstractmethod
from ldap_rbac.core import constants
from ldap_rbac.models import User, Role, Group, TokenUser
import six

PERMISSIONS = [
    constants.PERMISSION_READ_MASK,
    constants.PERMISSION_WRITE_MASK,
    constants.PERMISSION_EXECUTE_MASK,
    constants.PERMISSION_DELETE_MASK,
    constants.PERMISSION_LIST_MASK,
    constants.PERMISSION_INFO_MASK,
    constants.PERMISSION_X_WRITE_MASK
]


class AccessControlEntry(object):
    def __init__(self, sid=None,
                 allow_mask=None, deny_mask=None, grant_mask=None):
        self.sid = sid
        self.allow_mask = allow_mask if allow_mask is not None else constants.PERMISSION_BASE_MASK
        self.deny_mask = deny_mask if deny_mask is not None else constants.PERMISSION_BASE_MASK
        self.grant_mask = grant_mask if grant_mask is not None else constants.PERMISSION_BASE_MASK

    def allow(self, mask):
        self.allow_mask |= mask
        self.deny_mask &= ~mask

    def deny(self, mask):
        self.deny_mask |= mask
        self.allow_mask &= ~mask

    def manage(self, mask):
        self.grant_mask |= mask

    def dismiss(self, mask):
        self.grant_mask &= ~mask

    def is_allowed(self, mask):
        return (self.allow_mask & mask) > 0

    def is_denied(self, mask):
        return (self.deny_mask & mask) > 0

    def is_manager(self, mask):
        return (self.grant_mask & mask) > 0

    @property
    def hex_mask(self):
        return '%02x%02x%02x' % (
            self.allow_mask,
            self.deny_mask,
            self.grant_mask
        )

    def __str__(self):
        return '%s$%s' % (
            self.sid,
            self.hex_mask
        )


def entry_of(text, splitter='$'):
    sid, hex_mask = text.split(splitter)
    allow_mask, deny_mask, grant_mask = bytearray(hex_mask.decode("hex"))
    return AccessControlEntry(sid=sid, allow_mask=allow_mask, deny_mask=deny_mask, grant_mask=grant_mask)


def sid_of(who):
    if isinstance(who, User):
        return constants.SECURITY_IDENTITY_USER_PREFIX + who.id
    if isinstance(who, Role):
        return constants.SECURITY_IDENTITY_ROLE_PREFIX + who.cn
    if isinstance(who, Group):
        return constants.SECURITY_IDENTITY_GROUP_PREFIX + who.cn
    if isinstance(who, TokenUser):
        return constants.SECURITY_IDENTITY_USER_PREFIX + who.id
    return None


def sids_of(who):
    sid = sid_of(who)
    if sid is None:
        return []
    results = [sid]
    if isinstance(who, TokenUser):
        results += map(lambda name: constants.SECURITY_IDENTITY_USER_PREFIX + name, who.alias)
        results += map(lambda name: constants.SECURITY_IDENTITY_ROLE_PREFIX + name, who.roles)
        results += map(lambda name: constants.SECURITY_IDENTITY_GROUP_PREFIX + name, who.groups)
    return results


def default_entry(who):
    return AccessControlEntry(sid=sid_of(who))


class AccessControlList(object):
    def __init__(self, aces=None):
        if aces is not None:
            aces = {}
        self.default = map(entry_of, aces.get('def', []))
        self.extension = {k: map(entry_of, v) for k, v in six.iteritems(aces.get('ext', {}))}

    def entry(self, who, oid=None):
        sid = sid_of(who)
        aces = self.default if oid is None else self.extension.get(oid, [])
        for idx, ace in enumerate(self.aces):
            if ace.sid == sid:
                return idx, ace
        return -1, None, aces

    def exists(self, who, oid=None):
        idx, ace = self.entry(who, oid=oid)
        return idx >= 0

    def update(self, idx, ace, oid=None):
        if oid is None:
            if idx < 0:
                self.default.append(ace)
            else:
                self.default[idx] = ace
        else:
            if oid not in self.extension:
                self.extension[oid] = []
            if idx < 0:
                self.extension[oid].append(ace)
            else:
                self.extension[oid][idx] = ace

    def remove(self, idx, oid=None):
        if oid is None:
            del self.default[idx]
        else:
            del self.extension[oid][idx]

    def allow(self, who, permission_mask, oid=None):
        idx, ace = self.entry(who, oid=oid)
        if idx < 0:
            ace = default_entry(who)
        ace.allow(permission_mask)
        self.update(idx, ace, oid=oid)

    def deny(self, who, permission_mask, oid=None):
        idx, ace = self.entry(who, oid=oid)
        if idx < 0:
            ace = default_entry(who)
        ace.deny(permission_mask)
        self.update(idx, ace, oid=oid)

    def manage(self, who, permission_mask, oid=None):
        idx, ace = self.entry(who, oid=oid)
        if idx < 0:
            ace = default_entry(who)
        ace.manage(permission_mask)
        self.update(idx, ace, oid=oid)

    def dismiss(self, who, permission_mask, oid=None):
        idx, ace = self.entry(who, oid=oid)
        if idx < 0:
            ace = default_entry(who)
        ace.dismiss(permission_mask)
        self.update(idx, ace, oid=oid)

    def is_allowed(self, who, permission_mask, oid=None, default=False):
        sids = sids_of(who)
        aces = self.default if oid is None else self.extension.get(oid, [])
        for ace in aces:
            for sid in sids:
                if ace.sid == sid:
                    if ace.is_allowed(permission_mask):
                        return True
                    if ace.is_denied(permission_mask):
                        return False
        return default

    def is_manager(self, who, permission_mask, oid=None):
        sids = sids_of(who)
        aces = self.default if oid is None else self.extension.get(oid, [])
        for ace in aces:
            for sid in sids:
                if ace.sid == sid:
                    if ace.is_manager(permission_mask):
                        return True
        return False

    def permission_of(self, who, oid=None):
        mask = constants.PERMISSION_BASE_MASK
        for permission in PERMISSIONS:
            if self.is_allowed(who, permission, oid=oid):
                mask |= permission
        return mask

    def manager_of(self, who, oid=None):
        mask = constants.PERMISSION_BASE_MASK
        for permission in PERMISSIONS:
            if self.is_manager(who, permission, oid=oid):
                mask |= permission
        return mask

    @property
    def __dict__(self):
        return {
            'def': map(str, self.default),
            'ext': {k: map(str, v) for k, v in six.iteritems(self.extension)}
        }


class AccessControlListHelper(object):
    __metaclass__ = ABCMeta

    @property
    def type(self):
        return 'Base'

    @abstractmethod
    def load(self, resource, force=False):
        pass

    @abstractmethod
    def save(self, resource):
        pass

    @staticmethod
    def sids_of(who):
        return sids_of(who)
