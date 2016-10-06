# -*- coding: utf-8 -*-
from tinydb import Query
from ldap_rbac.resources.tags import Tags, TagsHelper


class TinyTags(TagsHelper):
    def __init__(self, db=None, table=None):
        self.db = db
        self.table = table

    @property
    def type(self):
        return 'TinyDB'

    def db(self):
        return self.table if self.table is not None else self.db

    def load(self, resource, force=False):
        if resource.loaded_tags is not None and not force:
            return
        if resource.helper.is_tag_together:
            tags = resource.underlying.get('tags', {})
        else:
            query = Query()
            result = self.db().get(query.rid == resource.rid)
            tags = {} if result is None else result.get('tags', {})
        resource.loaded_tags = Tags(resource, tags=tags)

    def save(self, resource):
        if resource.helper.is_tag_together:
            resource.underlying['tags'] = resource.loaded_tags.tags
        else:
            query = Query()
            if (self.db().get(query.rid == resource.rid)) is None:
                self.db().insert({
                    'rid': resource.rid,
                    'tags': resource.loaded_tags.tags
                })
            else:
                self.db().update({'tags': resource.loaded_tags.tags}, query.rid == resource.rid)
