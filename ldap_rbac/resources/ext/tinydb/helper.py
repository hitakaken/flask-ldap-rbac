# -*- coding: utf-8 -*-
import json

from tinydb import Query
from acls import TinyACLs
from tags import TinyTags
from logger import TinyLogger
from ldap_rbac.resources.helpers import ResourceHelper

inode_attrs = ['rid', 'owner', 'group', 'mode', 'type', 'ctime', 'mtime', 'atime', 'links', 'blocks']


class TinyResources(ResourceHelper):
    def __init__(self, root=None, acls=None, tags=None, logger=None,
                 db=None, enable_acl=True, enable_tags=True, enable_log=True,
                 enable_access_log=True, enable_operation_log=False):
        self.db = db
        if enable_acl and acls is None:
            acls = TinyACLs(db=db)
        if enable_tags and tags is None:
            tags = TinyTags(db=db)
        if enable_log and logger is None:
            logger = TinyLogger(db=db)
        super(TinyResources, self).__init__(
            root=root,
            acls=acls, tags=tags, logger=logger,
            enable_access_log=enable_access_log, enable_operation_log=enable_operation_log)

    @property
    def type(self):
        return 'TinyDB'

    def query_of_user(self, user=None):
        query = Query()
        # 超级管理员全部权限
        if user.is_admin:
            return query.rid.exists()
        sids = self.acls.sids_of(user)

        def check_access(aces):
            for ace in aces['def']:
                for sid in sids:
                    if ace.startswith(sid + '$') and not ace.startswith(sid + '$00'):
                        return True
            return False

        return (query.owner.test(lambda owner: owner in sids)) | \
               (query.acls.test(check_access))

    def query(self, dsl):
        pass

    def create(self, resource, user=None, **kwargs):
        if not resource.parent.loaded:
            resource.parent = self.find_by_path(resource.parent.path)
        resource.fill(user=user)
        entry = {}
        for attr in inode_attrs:
            entry[attr] = getattr(resource, attr)
        if resource.underlying is not None and 'data' in resource.underlying:
            entry['data'] = resource.underlying['data']
        elif resource.is_embed and resource.content is not None:
            entry['data'] = resource.content
        if resource.underlying is None:
            resource.underlying = {}
        if self.is_acl_together:
            self.acls.save(resource)
            entry['acls'] = resource.underlying.get('acls', {'def': [], 'ext': {}})
        if self.is_tag_together:
            self.tags.save(resource)
            entry['tags'] = resource.underlying.get('tags', {})
        entry['path'] = resource.helper.rel_path(resource.path)
        self.db.insert(entry)

    def load(self, resource, result):
        changes = []
        for attr in inode_attrs:
            if getattr(resource, attr) is None:
                setattr(resource, attr, result.get(attr))
            elif getattr(resource, attr) != result.get(attr):
                changes.append(attr)
        if resource.loaded_xattrs is None:
            resource.loaded_xattrs = result.get('xattrs', {})
        elif resource.loaded_xattrs != result.get('xattrs'):
            changes.append('xattrs')
        if self.is_acl_together:
            self.acls.load(resource)
        if self.is_tag_together:
            self.tags.load(resource)
        resource.loaded = True
        return resource, changes

    def find_by_path(self, path, **kwargs):
        if not path.startswith(self.root.path):
            return None
        rel_path = self.rel_path(path)
        if len(rel_path) == 0:
            return self.root
        query = Query()
        result = self.db.get(query.path == rel_path)
        if result is None:
            return result
        resource = self.instance_by_path(rel_path, underlying=result)
        resource, changes = self.load(resource, result)
        return resource

    def find_by_id(self, rid, **kwargs):
        query = Query()
        result = self.db.get(query.rid == rid)
        if result is None:
            return result
        resource = self.instance_by_path(self.root.path + result.get('path'), underlying=result)
        resource, changes = self.load(resource, result)
        return resource

    def find_all(self, query, **kwargs):
        results = self.db.search(query)
        temp = []
        for result in results:
            resource = self.instance_by_path(self.root.path + result.get('path'), underlying=result)
            resource, changes = self.load(resource, result)
            temp.append(resource)
        return temp

    def count(self, query, **kwargs):
        return self.db.count(query)

    def list(self, resource):
        pass

    def update(self, resource, user=None, **kwargs):
        update = {}
        for change in resource.changes:
            if change in inode_attrs:
                update[change] = getattr(resource, change)
            else:
                update[change] = resource.underlying[change]
        query = Query()
        self.db.update(update, query.rid == resource.rid)
        resource.changes = []

    def delete(self, path, user=None, **kwargs):
        pass

    def load_xattrs(self, resource):
        pass

    @property
    def is_acl_together(self):
        return self.is_acl_support and self.acls.type == self.type \
               and self.acls.db == self.db and self.acls.table is None

    @property
    def is_tag_together(self):
        return self.is_tag_support and self.tags.type == self.type \
               and self.tags.db == self.db and self.tags.table is None

    def read(self, resource):
        if resource.is_embed:
            return resource.underlying.get('data', {})

    def write(self, resource, content):
        if resource.is_embed:
            resource.underlying['data'] = content

    def append(self, resource, content):
        if resource.is_embed:
            resource.underlying['data'] = resource.underlying.get('data', {}).update(content)
