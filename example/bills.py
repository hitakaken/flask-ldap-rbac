# -*- coding: utf-8 -*-
from flask import current_app as app
from flask_login import current_user, login_required
from ldap_rbac.patched import Namespace, Resource, fields
from ldap_rbac.core import utils, exceptions
import six

api = Namespace('bill',
                title='Bills Management',
                version='1.0',
                description='',
                tags=['bill']
                )

auth_key = api.parser()
auth_key.add_argument('AuthToken', location='headers')

bill_issue = api.model('BillIssue', {
        'date': fields.Date(description='还贷日期', required=True),
        'days': fields.Integer(minimum=1, maximum=31, description='天数', required=True),
        'mount': fields.Fixed(decimals=2, description='利息金额', required=True),

    })
bill_form = api.model('BillForm', {
    'bank': fields.String(description='放贷银行', required=True),
    'company': fields.String(description='公司名称', required=True),
    'ioan': fields.Fixed(decimals=2, description='贷款金额', required=True),
    'rate_type': fields.String(description='利率类型', enum=['固定', '浮动'], required=True),
    'rate': fields.Fixed(decimals=4, description='利率', required=True),
    'annual_interest': fields.Fixed(decimals=2, description='年利息', required=True),
    'daily_interest': fields.Fixed(decimals=2, description='日利息', required=True),
    'lending_date': fields.Date(description='放款日', required=True),
    'expiry_date': fields.Date(description='到期日', required=True),
    'interest_days': fields.Integer(description='计息天数', required=True),
    'total': fields.Fixed(decimals=2, description='实际本息合计', required=True),
    'issues': fields.List(fields.Nested(bill_issue), description='每月账单', required=True),
})
bill_tags = api.model('BillTags', {
        'tag': fields.String,
        'users': fields.List(fields.String)
    })
bill_details = api.inherit('BillDetail', bill_form, {
    'rid': fields.String(descriptions='账单ID', required=True),
    'owner': fields.String(descriptions='所有者', required=True),
    'tags': fields.List(fields.Nested(bill_tags), descriptions='标签', required=True),
    'perms': fields.List(fields.String, descriptions='权限', required=True)
})


def wrap_detail(resource, user=None):
    resp = resource.underlying['data']
    resp['rid'] = resource.rid
    resp['owner'] = resource.owner.split(':')[1]
    resp['issues'] = resource.underlying['data']['issues']
    resp['tags'] = []
    for k, v in six.iteritems(resource.tags.list_all(user=user)):
        resp['tags'].append({'tag': k, 'users': v})
    resp['perms'] = []
    if resource.can_read(user=user):
        resp['perms'].append('R')
    if resource.can_write(user=user):
        resp['perms'].append('W')
    if resource.can_tags(user=user):
        resp['perms'].append('T')
    if resource.can_manage_read(user=user):
        resp['perms'].append('GR')
    if resource.can_manage_write(user=user):
        resp['perms'].append('GW')
    if resource.can_manage_tags(user=user):
        resp['perms'].append('GT')
    return resp


@api.route('/list')
class ListBills(Resource):

    @api.expect(auth_key)
    @api.marshal_with(bill_details, as_list=True)
    @api.doc(id='list_bills', security='apiKey')
    # @login_required
    def get(self):
        query = app.resources.query_of_user(user=current_user)
        resources = app.resources.find_all(query)
        results = []
        for resource in resources:
            results.append(wrap_detail(resource, user=current_user))
        return results


@api.route('/create')
class CreateBill(Resource):

    @api.expect(bill_form, auth_key)
    @api.marshal_with(bill_details)
    @api.doc(id='create_bill', security='apiKey')
    @login_required
    def post(self):
        data = app.rest.payload
        rid = utils.uuid()
        name = rid + '.json'
        res = app.resources.instance(name=name, content=data)
        res.rid = rid
        app.resources.create(res, user=current_user)
        resource = app.resources.find_by_id(rid)
        app.resources.log(resource, event={'act': 'create_bill'}, user=current_user)
        return wrap_detail(resource, user=current_user)


@api.route('/detail/<rid>', endpoint='bill_detail')
@api.doc(params={'rid': u'账单ID'}, security='apiKey')
class BillDetails(Resource):

    @api.expect(auth_key)
    @api.doc(id='view_bill')
    def get(self, rid):
        """
        View Bill Details

        :raises FuseError: Bill not exists or not permission
        :raises SecurityException: User session failed
        """
        resource = app.resources.find_by_id(rid)
        if resource is None:
            raise exceptions.ENOENT
        if not resource.can_read(user=current_user):
            raise exceptions.EACCES
        app.resources.log(resource, event={'act': 'read_bill'}, user=current_user)
        return wrap_detail(resource, user=current_user)

    @api.expect(bill_form, auth_key)
    @api.marshal_with(bill_details)
    @api.doc(id='update_bill', security='apiKey')
    @login_required
    def post(self, rid):
        resource = app.resources.find_by_id(rid)
        if resource is None:
            raise exceptions.ENOENT
        if not resource.can_write(user=current_user):
            raise exceptions.EACCES
        data = app.rest.payload
        resource.underlying['data'] = data
        resource.changes.append('data')
        app.resources.update(resource, user=current_user)
        app.resources.log(resource, event={'act': 'update_bill'}, user=current_user)
        result = app.resources.find_by_id(rid)
        return wrap_detail(result, user=current_user)


@api.route('/tags/<rid>/<tag>')
@api.doc(params={'rid': u'账单ID', 'tag': u'标签'}, security='apiKey')
class BillTag(Resource):

    @api.expect(auth_key)
    @api.doc(id='add_tag')
    def post(self, rid, tag):
        resource = app.resources.find_by_id(rid)
        if resource is None:
            raise exceptions.ENOENT
        if not resource.can_tags(user=current_user):
            raise exceptions.EACCES
        resource.tags.tag(tag, user=current_user)
        app.resources.tags.save(resource)
        app.resources.update(resource, user=current_user)
        app.resources.log(resource, event={'act': 'add_tag', 'tag': tag}, user=current_user)
        return {'success': True}, 200

    @api.expect(auth_key)
    @api.doc(id='del_tag')
    def delete(self, rid, tag):
        resource = app.resources.find_by_id(rid)
        if resource is None:
            raise exceptions.ENOENT
        if not resource.can_tags(user=current_user):
            raise exceptions.EACCES
        resource.tags.untag(tag, user=current_user)
        app.resources.tags.save(resource)
        app.resources.update(resource, user=current_user)
        app.resources.log(resource, event={'act': 'del_tag', 'tag': tag}, user=current_user)
        return {'success': True}, 200


@api.route('/perms/<rid>/<perms>/<uid>')
class BillPerms(Resource):
    @api.expect(auth_key)
    @api.doc(id='grant')
    def post(self, rid, perms, uid):
        resource = app.resources.find_by_id(rid)
        if resource is None:
            raise exceptions.ENOENT
        perms = perms.split(',')
        user = app.rbac.users.find_one(uid)
        if user is None:
            raise exceptions.USER_NOT_FOUND
        user = app.rbac.tokens.token_user(user=user)
        if 'R' in perms:
            resource.grant_read(user=user, manager=current_user)
        if 'W' in perms:
            resource.grant_write(user=user, manager=current_user)
        if 'T' in perms:
            resource.grant_tags(user=user, manager=current_user)
        if 'GR' in perms:
            resource.grant_manage_read(user=user, manager=current_user, ignore=True)
        if 'GW' in perms:
            resource.grant_manage_write(user=user, manager=current_user)
        if 'GT' in perms:
            resource.grant_manage_tags(user=user, manager=current_user, ignore=True)
        app.resources.acls.save(resource)
        app.resources.update(resource, user=current_user)
        app.resources.log(resource, event={'act': 'grant', 'user': user.id}, user=current_user)
        return {'success': True}, 200

    @api.expect(auth_key)
    @api.doc(id='revoke')
    def delete(self, rid, perms, uid):
        resource = app.resources.find_by_id(rid)
        if resource is None:
            raise exceptions.ENOENT
        perms = perms.split(',')
        user = app.rbac.users.find_one(uid)
        if user is None:
            raise exceptions.USER_NOT_FOUND
        if 'GR' in perms:
            resource.revoke_manage_read(user=user, manager=current_user, ignore=True)
        if 'GW' in perms:
            resource.revoke_manage_write(user=user, manager=current_user)
        if 'GT' in perms:
            resource.revoke_manage_tags(user=user, manager=current_user, ignore=True)
        if 'R' in perms:
            resource.revoke_read(user=user, manager=current_user)
        if 'W' in perms:
            resource.revoke_write(user=user, manager=current_user)
        if 'T' in perms:
            resource.revoke_tags(user=user, manager=current_user)
        app.resources.acls.save(resource)
        app.resources.update(resource, user=current_user)
        app.resources.log(resource, event={'act': 'revoke', 'user': user.id}, user=current_user)
        return {'success': True}, 200