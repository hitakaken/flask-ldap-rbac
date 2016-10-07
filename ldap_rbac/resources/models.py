# -*- coding: utf-8 -*-
import datetime
from ldap_rbac.core import constants, exceptions, utils
from ldap_rbac.models import User, TokenUser
import acls

# 资源类型
RESOURCE_TYPE_EMBED = 0  # 内嵌数据
RESOURCE_TYPE_LINK = 1  # 内部软连接
RESOURCE_TYPE_FILE = 2  # 本地文件
RESOURCE_TYPE_URL = 3  # 外部链接


def timestamp_now():
    """当前时间时间戳"""
    return utils.to_timestamp(datetime.datetime.utcnow())


def is_admin(user):
    return user is not None and hasattr(user, 'is_admin') and user.is_admin


class Resource(object):
    """资源对象"""
    def __init__(self, parent=None, name=None, rid=None,
                 owner=None, group=None, mode=None, children=None,
                 ctype=None, content=None,
                 ctime=None, mtime=None, atime=None, links=None, blocks=None,
                 helper=None, underlying=None):
        self.parent = parent
        self.name = name
        self.rid = rid
        self.owner = owner
        self.group = group
        self.children = children
        self.mode = mode
        self.type = ctype
        self.content = content
        self.ctime = ctime
        self.mtime = mtime
        self.atime = atime
        self.links = links
        self.blocks = blocks
        self.helper = helper
        self.loaded = False
        self.loaded_acls = None
        self.loaded_xattrs = None
        self.loaded_tags = None
        self.changes = []
        self.underlying = underlying

    def fill(self, user=None):
        """创建时，默认填充"""
        if self.rid is None:
            self.rid = utils.uuid()
        if self.owner is None:
            self.set_owner(user=user)
        if self.group is None:
            if user.group is not None:
                self.group = constants.SECURITY_IDENTITY_GROUP_PREFIX + user.group
            else:
                self.group = constants.SECURITY_IDENTITY_GROUP_PREFIX + constants.ROLE_NAME_NOBODY
        if self.mode is None:
            self.mode = 0o740
        if self.type is None:
            self.type = RESOURCE_TYPE_EMBED
        if self.content is None:
            if self.is_embed:
                self.content = {}
        ts = timestamp_now()
        if self.ctime is None:
            self.ctime = ts
        if self.mtime is None:
            self.mtime = ts
        if self.atime is None:
            self.atime = ts
        if self.links is None:
            self.links = []
        if self.blocks is None:
            self.blocks = []

    @property
    def path(self):
        return '' if self.parent is None else '%s/%s' % (
            self.parent.path,
            self.name
        )

    @property
    def is_branch(self):
        return self.children is not None

    @property
    def is_leaf(self):
        return self.children is None

    @property
    def is_embed(self):
        return self.type == RESOURCE_TYPE_EMBED

    @property
    def is_link(self):
        return self.type == RESOURCE_TYPE_LINK

    @property
    def is_link_to_file(self):
        return self.type == RESOURCE_TYPE_FILE

    @property
    def is_link_to_url(self):
        return self.type == RESOURCE_TYPE_URL

    def set_owner(self, user=None):
        self.owner = acls.sid_of(user)

    @staticmethod
    def is_admin(user=None):
        return is_admin(user)

    def has_owner(self, user=None):
        sids = acls.sids_of(user)
        return self.owner in sids

    def set_group(self, group=None):
        self.group = acls.sids_of(group)

    def has_group(self, group=None):
        if self.group is None:
            return False
        sids = acls.sids_of(group)
        return self.group in sids

    def can_read(self, user=None):
        if is_admin(user):
            return True
        if self.has_owner(user=user) and self.mode & 0o400 > 0:
            return True
        if self.has_group(group=user) and self.mode & 0o040 > 0:
            return True
        if self.acls is not None:
            return self.acls.is_allowed(
                user, constants.PERMISSION_READ_MASK,
                default=self.mode & 0o004 > 0)
        return self.mode & 0o004 > 0

    def can_manage_read(self, user=None):
        if is_admin(user) or self.has_owner(user=user):
            return True
        if self.acls is not None:
            return self.acls.is_manager(user, constants.PERMISSION_READ_MASK)
        return False

    def grant_read(self, user=None, manager=None):
        if not self.can_manage_read(user=manager):
            raise exceptions.EPERM
        if not self.can_read(user=user):
            if self.has_owner(user=user):
                self.mode |= 0o400
            elif self.has_group(group=user):
                self.mode |= 0o040
            elif self.acls is not None:
                self.acls.allow(user, constants.PERMISSION_READ_MASK)

    def revoke_read(self, user=None, manager=None):
        if not self.can_manage_read(user=manager):
            raise exceptions.EPERM
        if self.can_read(user) and (not self.can_manage_read(user) or (is_admin(manager) or self.has_owner(manager))):
            if self.has_owner(user=user):
                self.mode &= ~0o400
            elif self.has_group(group=user):
                self.mode &= ~0o040
            elif self.acls is not None:
                self.acls.deny(user, constants.PERMISSION_READ_MASK)
            else:
                raise exceptions.EPERM
        else:
            raise exceptions.EPERM

    def grant_manage_read(self, user=None, manager=None, ignore=False):
        if ((is_admin(manager) or self.has_owner(user=manager))
                and not (is_admin(user) or self.has_owner(user=user))
                and self.acls is not None) or (ignore and self.can_manage_read(user=manager)):
            self.acls.manage(user, constants.PERMISSION_READ_MASK)
        else:
            raise exceptions.EPERM

    def revoke_manage_read(self, user=None, manager=None, ignore=False):
        if ((is_admin(manager) or self.has_owner(user=manager))
                and not (is_admin(user) or self.has_owner(user=user))
                and self.acls is not None) or (ignore and self.can_manage_read(user=manager)):
            self.acls.dismiss(user, constants.PERMISSION_READ_MASK)
        else:
            raise exceptions.EPERM

    def can_write(self, user=None):
        if is_admin(user):
            return True
        if self.has_owner(user=user) and self.mode & 0o200 > 0:
            return True
        if self.has_group(group=user) and self.mode & 0o020 > 0:
            return True
        if self.acls is not None:
            return self.acls.is_allowed(
                user, constants.PERMISSION_WRITE_MASK,
                default=self.mode & 0o002 > 0)
        return self.mode & 0o002 > 0

    def can_manage_write(self, user=None):
        if is_admin(user) or self.has_owner(user=user):
            return True
        if self.acls is not None:
            return self.acls.is_manager(user, constants.PERMISSION_WRITE_MASK)
        return False

    def grant_write(self, user=None, manager=None):
        if not self.can_manage_write(user=manager):
            raise exceptions.EPERM
        if not self.can_write(user=user):
            if self.has_owner(user=user):
                self.mode |= 0o200
            elif self.has_group(group=user):
                self.mode |= 0o020
            elif self.acls is not None:
                self.acls.allow(user, constants.PERMISSION_WRITE_MASK)

    def revoke_write(self, user=None, manager=None):
        if not self.can_manage_write(user=manager):
            raise exceptions.EPERM
        if self.can_write(user) and (not self.can_manage_write(user) or (is_admin(manager) or self.has_owner(manager))):
            if self.has_owner(user=user):
                self.mode &= ~0o200
            elif self.has_group(group=user):
                self.mode &= ~0o020
            elif self.acls is not None:
                self.acls.deny(user, constants.PERMISSION_WRITE_MASK)
            else:
                raise exceptions.EPERM
        else:
            raise exceptions.EPERM

    def grant_manage_write(self, user=None, manager=None):
        if (is_admin(manager) or self.has_owner(user=manager)) \
                and not (is_admin(user) or self.has_owner(user=user)) \
                and self.acls is not None:
            self.acls.manage(user, constants.PERMISSION_WRITE_MASK)
        else:
            raise exceptions.EPERM

    def revoke_manage_write(self, user=None, manager=None):
        if (is_admin(manager) or self.has_owner(user=manager)) \
                and not (is_admin(user) or self.has_owner(user=user)) \
                and self.acls is not None:
            self.acls.dismiss(user, constants.PERMISSION_WRITE_MASK)
        else:
            raise exceptions.EPERM

    def can_tags(self, user=None):
        if self.acls is None:
            return self.can_read(user=user)
        if is_admin(user) or self.has_owner(user=user) or self.has_group(group=user):
            return True
        if self.acls is not None:
            return self.acls.is_allowed(
                user, constants.PERMISSION_TAGS_MASK)
        return False

    def can_manage_tags(self, user=None):
        if is_admin(user) or self.has_owner(user=user):
            return True
        if self.acls is not None:
            return self.acls.is_manager(user, constants.PERMISSION_TAGS_MASK)
        return False

    def grant_tags(self, user=None, manager=None):
        if not self.can_manage_tags(user=manager):
            raise exceptions.EPERM
        if self.acls is None:
            self.grant_read(user=user, manager=manager)
        elif not self.can_tags(user):
            if self.has_owner(user=user):
                self.mode |= 0o400
            elif self.has_group(group=user):
                self.mode |= 0o040
            elif self.acls is not None:
                self.acls.allow(user, constants.PERMISSION_TAGS_MASK)

    def revoke_tags(self, user=None, manager=None):
        if not self.can_manage_tags(user=manager):
            raise exceptions.EPERM
        if self.can_tags(user) and (not self.can_manage_tags(user) or (is_admin(manager) or self.has_owner(manager))):
            if self.has_owner(user=user):
                self.mode &= ~0o400
            elif self.has_group(group=user):
                self.mode &= ~0o040
            elif self.acls is not None:
                self.acls.deny(user, constants.PERMISSION_TAGS_MASK)

    def grant_manage_tags(self, user=None, manager=None, ignore=False):
        if (is_admin(manager) or self.has_owner(user=manager)
                and self.acls is not None) or (ignore and self.can_manage_tags(user=manager)):
            self.acls.manage(user, constants.PERMISSION_TAGS_MASK)
        else:
            raise exceptions.EPERM

    def revoke_manage_tags(self, user=None, manager=None, ignore=False):
        if (is_admin(manager) or self.has_owner(user=manager)
                and not (is_admin(user) or self.has_owner(user=user))
                and self.acls is not None) or (ignore and self.can_manage_tags(user=manager)):
            self.acls.dismiss(user, constants.PERMISSION_TAGS_MASK)
        else:
            raise exceptions.EPERM

    def read(self, user=None):
        if not self.can_read(user):
            raise exceptions.EPERM
        if self.helper is not None:
            return self.helper.read(self)

    def write(self, content, user=None):
        if not self.can_write(user):
            raise exceptions.EPERM
        if self.helper is not None:
            return self.helper.write(self, content)

    def append(self, content, user=None):
        if not self.can_write(user):
            raise exceptions.EPERM
        if self.helper is not None:
            return self.helper.append(self, content)

    @property
    def acls(self, force=False):
        if (self.loaded_acls is None or force) and self.helper is not None and self.helper.is_acl_support:
            self.helper.load_acls(self)
        return self.loaded_acls

    @property
    def xattrs(self, force=False):
        if (self.loaded_xattrs is None or force) and self.helper is not None and self.helper.is_xattr_support:
            self.helper.load_xattrs(self)
        return self.loaded_xattrs

    @property
    def tags(self, force=False):
        if (self.loaded_tags is None or force) and self.helper is not None and self.helper.is_tag_support:
            self.helper.load_tags(self)
        return self.loaded_tags
