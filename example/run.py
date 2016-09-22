# -*- coding: utf-8 -*-
from flask import Flask
from ldap_rbac import RBACManager
import settings

app = Flask(__name__)
app.config.from_object(settings)
manager = RBACManager(app)

if __name__ == '__main__':
    app.run(debug=True)
