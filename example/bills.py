# -*- coding: utf-8 -*-
from flask import current_app as app, request
from flask_login import current_user, login_required
from flask_restplus import reqparse
from ldap_rbac.patched import Namespace, Resource, fields
from ldap_rbac.core import utils
import six

api = Namespace('bill',
                title='Bills Management',
                version='1.0',
                description='',
                tags=['bill']
                )

tag_schema = api.model('Tag', {
        'tag': fields.String,
        'users': fields.List(fields.String)
    })
issue_schema = api.model('Issue', {
        'date': fields.String,
        'mount': fields.String,
        'days': fields.String
    })

bill_info = api.model('Bill', {
    'bank': fields.String,
    'company': fields.String,
    'ioan': fields.String,
    'rate': fields.String,
    'annual_interest': fields.String,
    'daily_interest': fields.String,
    'lending_date': fields.String,
    'expiry_date': fields.String,
    'interest_days': fields.String,
    'total': fields.String,
    'issues': fields.List(fields.Nested(issue_schema)),
    'tags': fields.List(fields.Nested(tag_schema)),
    'permission': fields.List(fields.String)
})


bill_fields = ['bank', 'company', 'ioan', 'type', 'rate', 'annual_interest', 'daily_interest',
               'lending_date', 'expiry_date', 'interest_days', 'total']
bill_form = reqparse.RequestParser()
bill_form.add_argument('bank', required=True, location='form')
bill_form.add_argument('company', required=True, location='form')
bill_form.add_argument('ioan', required=True, location='form')
# bill_form.add_argument('type', choices=('fix', 'dyn'), location='form')
bill_form.add_argument('rate', required=True, location='form')
bill_form.add_argument('annual_interest', required=True, location='form')
bill_form.add_argument('daily_interest', required=True, location='form')
bill_form.add_argument('lending_date', required=True, location='form')
bill_form.add_argument('expiry_date', required=True, location='form')
bill_form.add_argument('interest_days', required=True, location='form')
bill_form.add_argument('total', required=True, location='form')
bill_form.add_argument('issues', action='append', location='form')


def wrap_detail(resource, user=None):
    resp = {}
    for field in bill_fields:
        resp[field] = resource.underlying['data'][field]
    resp['issues'] = resource.underlying['data']['issues']
    resp['tags'] = []
    for k, v in six.iteritems(resource.list_all(user=user)):
        resp['tags'].append({'tag': k, 'users': v})
    resp['permission'] = []
    if resource.can_read(user=user):
        resp['permission'].append('R')
    if resource.can_write(user=user):
        resp['permission'].append('W')
    if resource.can_tag(user=user):
        resp['permission'].append('T')
    if resource.can_manage_read(user=user):
        resp['permission'].append('GR')
    if resource.can_manage_write(user=user):
        resp['permission'].append('GW')
    if resource.can_manage_tag(user=user):
        resp['permission'].append('GT')
    return resp


@api.route('/list')
class ListBills(Resource):
    @api.doc(id='list_bills')
    @api.marshal_with(bill_info, as_list=True)
    # @login_required
    def get(self):
        print current_user.name
        return []


@api.route('/create')
class CreateBill(Resource):
    @api.doc(id='create_bill')
    @api.expect(bill_form)
    @api.marshal_with(bill_info)
    @api.doc(security='apikey')
    # @login_required
    def post(self):
        print 'start'
        print request.headers
        print request.values
        args = bill_form.parse_args()
        print args
        data = {}
        for field in bill_fields:
            data[field] = args[field]
        data['issues'] = []
        print args['issues']
        for issue in args['issues']:
            print issue
            date, days, mount = issue.split('$')
            data['issues'].append({'date': date, 'mount': mount, 'days': days})
        rid = utils.uuid()
        name = rid + '.json'
        res = app.resources.instance(name=name, underlying={'data': data})
        res.rid = rid
        app.resources.create(res, user=current_user)
        result = app.resources.find_by_id(rid)
        return wrap_detail(result, user=current_user)


@api.route('/detail/<rid>', endpoint='bill_detail')
@api.doc(params={'rid': u'账单ID'})
@api.doc(security='apikey')
class BillDetails(Resource):
    @api.doc(id='view_bill')
    def get(self, rid):
        return {}


class Tag(Resource):
    def post(self):
        pass

    def delete(self):
        pass
