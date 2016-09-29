
class ResourceHelper(object):
    __metaclass__ = ABCMeta

    def __init__(self, root=None, acls=None, tags=None, logger=None,
                 enable_access_log=True, enable_operation_log=False):
        if root is None:
            root = Resource(name='', rid='ROOT',
                            owner=constants.SECURITY_IDENTITY_ROLE_PREFIX + constants.ROLE_NAME_ADMIN,
                            group=constants.SECURITY_IDENTITY_ROLE_PREFIX + constants.ROLE_NAME_LOGIN_USER,
                            mode=0b111100000, children=[], ctime=0, mtime=0, atime=0, links=[], blocks=[],
                            helper=self)
        self.root = root
        self.root.loaded = True
        self.acls = acls
        self.tags = tags
        self.logger = logger
        self.enable_access_log = enable_access_log
        self.enable_operation_log = enable_operation_log

    @abstractmethod
    def query_of_user(self, user=None):
        pass

    @abstractmethod
    def query(self, dsl):
        pass

    @property
    def is_acl_support(self):
        return self.acls is not None

    def load_acls(self, resource):
        if self.is_acl_support:
            self.acls.load(resource)
        pass

    def add_acls(self, resource, aces, user=None):
        if self.is_acl_support:
            self.acls.add(resource, aces, user=user)
        else:
            pass

    def remove_acls(self, resource, sids, user=None):
        if self.is_acl_support:
            self.acls.add(resource, sids, user=user)
        else:
            pass

    def clear_acls(self, resource, user=None):
        if self.is_acl_support:
            self.acls.clear(resource, user=user)
        else:
            pass

    @property
    def is_xattr_support(self):
        return False

    @abstractmethod
    def load_xattrs(self, resource):
        pass

    def update_xattrs(self, resource, xattrs):
        self.load_xattrs(resource)
        resource.loaded_xattrs.update(xattrs)

    def remove_xattrs(self, resource, keys):
        self.load_xattrs(resource)
        for key in keys:
            if key in resource.loaded_xattrs:
                del resource.loaded_xattrs[key]

    def clear_xattrs(self, resource):
        resource.loaded_xattrs = {}

    @property
    def is_tag_support(self):
        return self.acls is not None

    def load_tags(self, resource):
        if self.is_tag_support:
            return self.tags.load(resource)
        pass

    def add_tags(self, resource, tags, user=None):
        if self.is_tag_support:
            self.tags.add(resource, tags, user=user)
        else:
            pass

    def remove_tags(self, resource, tags, user=None):
        if self.is_tag_support:
            self.tags.remove(resource, tags, user=user)
        else:
            pass

    def clear_tags(self, resource, user=None):
        if self.is_tag_support:
            self.tags.clear(resource, user=user)
        else:
            pass

    @property
    def is_log_support(self):
        return self.logger is not None

    def log(self, resource, event=None, user=None, **kwargs):
        if self.is_log_support:
            self.logger.log(resource, event=event, user=user, **kwargs)

    def rel_path(self, path):
        return path[len(self.root.path):]

    def instance_by_path(self, path):
        if not path.startswith(self.root.path):
            return None
        rel_path = self.rel_path(path)
        if len(rel_path) == 0:
            return self.root
        names = rel_path.split('/')
        current = self.root
        for idx in range(0, len(names)):
            current = Resource(parent=current, name=names[idx], helper=self)
        return current

    def instance(self, parent=None, name=None, **kwargs):
        parent = self.root if parent is None else parent
        return Resource(parent=parent, name=name, helper=self, **kwargs)

    @abstractmethod
    def create(self, resource, user=None, **kwargs):
        pass

    @abstractmethod
    def find_by_path(self, path, **kwargs):
        if path == self.root.path:
            return self.root
        return None

    @abstractmethod
    def find_by_id(self, rid, **kwargs):
        if rid == self.root.rid:
            return self.root
        return None

    def find_one(self, path=None, rid=None, **kwargs):
        if path is not None:
            return self.find_by_path(path=path, **kwargs)
        if rid is not None:
            return self.find_by_id(rid=rid, **kwargs)

    @abstractmethod
    def find_all(self, query, **kwargs):
        pass

    @abstractmethod
    def count(self, query, **kwargs):
        pass

    def exists(self, path=None, rid=None, **kwargs):
        return self.find_one(path=path, rid=rid, **kwargs) is not None

    @abstractmethod
    def list(self, resource):
        pass

    @abstractmethod
    def update(self, resource, user=None, **kwargs):
        pass

    @abstractmethod
    def delete(self, path, user=None, **kwargs):
        pass