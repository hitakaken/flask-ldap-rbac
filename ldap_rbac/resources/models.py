# -*- coding: utf-8 -*-
import datetime
from abc import ABCMeta, abstractmethod
from ldap_rbac.core import constants, utils
from ldap_rbac.models import User, TokenUser
import acls

# 资源类型
RESOURCE_TYPE_EMBED = 0 # 内嵌数据
RESOURCE_TYPE_LINK = 1 # 内部软连接
RESOURCE_TYPE_FILE = 2 # 本地文件
RESOURCE_TYPE_URL = 3 # 外部链接


def timestamp_now():
    """当前时间时间戳"""
    return utils.to_timestamp(datetime.datetime.utcnow())


def is_admin(user):
    return user is not None and (isinstance(user, User) or isinstance(user, TokenUser)) and user.is_admin


class Resource(object):
    """资源对象"""
    __metaclass__ = ABCMeta

    def __init__(self, parent=None, name=None, rid=None,
                 owner=None, group=None, mode=None, children=None,
                 ctype=None, content=None,
                 ctime=None, mtime=None, atime=None, links=None, blocks=None,
                 helper=None):
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

    def fill(self, user=None):
        """创建时，默认填充"""
        if self.rid is None:
            self.rid = utils.uuid()
        if self.owner is None:
            self.set_owner(user)
        if self.group is None:
            if user.group is not None:
                self.group = constants.SECURITY_IDENTITY_GROUP_PREFIX + user.group
            else:
                self.group = constants.SECURITY_IDENTITY_GROUP_PREFIX + constants.ROLE_NAME_NOBODY
        if self.mode is None:
            self.mode = 0o750
        if self.type is None:
            self.type = RESOURCE_TYPE_EMBED
        if self.content is None:
            if self.is_embed():
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
        return '%s/%s' % (
            '' if self.parent is None else self.parent.path,
            self.name
        )

    def is_branch(self):
        return self.children is not None

    def is_leaf(self):
        return self.children is None

    def is_embed(self):
        return self.type == RESOURCE_TYPE_EMBED

    def is_link(self):
        return self.type == RESOURCE_TYPE_LINK

    def is_link_to_file(self):
        return self.type == RESOURCE_TYPE_FILE

    def is_link_to_url(self):
        return self.type == RESOURCE_TYPE_URL

    def set_owner(self, user=None):
        self.owner = acls.sid_of(user)

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
        if self.has_owner(user=user) and self.mode & 0o500 > 0:
            return True
        if self.has_group(group=user) and self.mode & 0o050 > 0:
            return True
        if self.acls is not None:
            return self.acls.is_allowed(
                user, constants.PERMISSION_READ_MASK,
                default=self.mode & 0o005 > 0)
        return self.mode & 0o005 > 0

    def can_grant_read(self, user=None):
        if is_admin(user):
            return True
        if self.has_owner(user=user):
            return True
        if self.acls is not None:
            return self.acls.is_manager(user, constants.PERMISSION_READ_MASK)
        return False

    def grant_read(self, user=None, manager=None):
        pass

    def revoke_read(self, user=None, manager=None):
        pass

    def can_write(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def can_grant_write(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def grant_write(self, user=None, manager=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def revoke_write(self, user=None, manager=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def can_info(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def can_grant_info(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def grant_info(self, user=None, manager=None):
        pass

    def revoke_info(self, user=None, manager=None):
        pass

    def can_list(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def can_grant_list(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def can_read_tags(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def can_grant_read_tags(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def grant_read_tags(self, user=None, manager=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def revoke_read_tags(self, user=None, manager=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def can_write_tags(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def can_grant_write_tags(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def grant_write_tags(self, user=None, manager=None):
        pass

    def revoke_write_tags(self, user=None, manager=None):
        pass

    def can_read_xattrs(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def can_grant_read_xattrs(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def grant_read_xattrs(self, user=None, manager=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def revoke_read_xattrs(self, user=None, manager=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def can_write_xattrs(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def can_grant_write_xattrs(self, user=None):
        if isinstance(user, User) or isinstance(user, TokenUser) and user.is_admin:
            return True
        pass

    def grant_write_xattrs(self, user=None, manager=None):
        pass

    def revoke_write_xattrs(self, user=None, manager=None):
        pass

    @abstractmethod
    def data(self):
        pass

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
        if (self.loaded_tags is None or force) and self.helper is not None and self.helper.is_xattr_support:
            self.loaded_tags = self.helper.load_tags(self)
        return self.loaded_tags
