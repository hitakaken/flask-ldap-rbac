# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    licenses = f.read()

install_requires = [
    'flask',
    'six',
    'python-ldap',
    'PyJWT',
    'flask-restplus',
    'apispec',
    'webargs',
    'flask-marshmallow',
    # 'flask-cors',
    'flatdict',
    'bidict',
    'bson'
]

setup(
    name='flask-ldap-rbac',
    version='0.0.1',
    description='基于LDAP的用户认证 Flask Blueprint',
    long_description=readme,
    author='CaoKe',
    author_email='hitakaken@gmail.com',
    url='https://github.com/hitakaken/flask-ldap-rbac',
    license=licenses,
    platforms=["any"],
    packages=[
        'ldap_rbac',
        'ldap_rbac/controllers',
        'ldap_rbac/core',
        'ldap_rbac/extensions',
        'ldap_rbac/resources',
        'ldap_rbac/helpers',
        'ldap_rbac/manager',
        'ldap_rbac/models',
        'ldap_rbac/patched'
    ],
    test_suite="test.tests",
    install_requires=install_requires,
    tests_require=['nose'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
    # data_files=[('', ['README'])]
)