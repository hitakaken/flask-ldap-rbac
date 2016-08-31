# -*- coding: utf-8 -*-
"""
[Configuring and securing PYTHON LDAP Applications Part 2]
(https://www.packtpub.com/books/content/configuring-and-securing-python-ldap-applications-part-2)
"""
import ldif, hashlib, uuid, os
from StringIO import StringIO
from ldap.cidict import cidict


def get_search_results(results):
    """Given a set of results, return a list of LDAPSearchResult objects."""
    res = []

    if type(results) == tuple and len(results) == 2:
        (code, arr) = results
    elif type(results) == list:
        arr = results

    if len(results) == 0:
        return res

    for item in arr:
        res.append(LDAPSearchResult(item))

    return res


class LDAPSearchResult:
    """A class to model LDAP results."""

    dn = ''

    def __init__(self, entry_tuple):
        """Create a new LDAPSearchResult object."""
        (dn, attrs) = entry_tuple
        if dn:
            self.dn = dn
        else:
            return

        self.attrs = cidict(attrs)

    def get_attributes(self):
        """Get a dictionary of all attributes.
        get_attributes()->{'name1':['value1','value2',...], 'name2: [value1...]}
        """
        return self.attrs

    def set_attributes(self, attr_dict):
        """Set the list of attributes for this record.

        The format of the dictionary should be string key, list of
        string alues. e.g. {'cn': ['M Butcher','Matt Butcher']}

        set_attributes(attr_dictionary)
        """

        self.attrs = cidict(attr_dict)

    def has_attribute(self, attr_name):
        """Returns true if there is an attribute by this name in the
        record.

        has_attribute(string attr_name)->boolean
        """
        return self.attrs.has_key(attr_name)

    def get_attr_values(self, key):
        """Get a list of attribute values.
        get_attr_values(string key)->['value1','value2']
        """
        return self.attrs[key]

    def get_attr_names(self):
        """Get a list of attribute names.
        get_attr_names()->['name1','name2',...]
        """
        return self.attrs.keys()

    def get_dn(self):
        """Get the DN string for the record.
        get_dn()->string dn
        """
        return self.dn

    def pretty_print(self):
        """Create a nice string representation of this object.

        pretty_print()->string
        """
        text = "DN: " + self.dn + "n"
        for a, v_list in self.attrs.iteritems():
            text = text + "Name: " + a + "n"
            for v in v_list:
                text = text + "  Value: " + v + "n"
        text += "========"
        return text

    def to_ldif(self):
        """Get an LDIF representation of this record.

        to_ldif()->string
        """
        out = StringIO()
        ldif_out = ldif.LDIFWriter(out)
        ldif_out.unparse(self.dn, self.attrs)
        return out.getvalue()


def check_password(tagged_digest_salt, password):
    """
    Checks the OpenLDAP tagged digest against the given password
    """
    # the entire payload is base64-encoded
    assert tagged_digest_salt.startswith('{SSHA}')

    # strip off the hash label
    digest_salt_b64 = tagged_digest_salt[6:]

    # the password+salt buffer is also base64-encoded.  decode and split the
    # digest and salt
    digest_salt = digest_salt_b64.decode('base64')
    digest = digest_salt[:20]
    salt = digest_salt[20:]

    sha = hashlib.sha1(password)
    sha.update(salt)

    return digest == sha.digest()


def make_secret(password):
    """
    Encodes the given password as a base64 SSHA hash+salt buffer
    """
    salt = os.urandom(4)

    # hash the password and append the salt
    sha = hashlib.sha1(password)
    sha.update(salt)

    # create a base64 encoded string of the concatenated digest + salt
    digest_salt_b64 = '{}{}'.format(sha.digest(), salt).encode('base64').strip()

    # now tag the digest above with the {SSHA} tag
    tagged_digest_salt = '{{SSHA}}{}'.format(digest_salt_b64)

    return tagged_digest_salt
