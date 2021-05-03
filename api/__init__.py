import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config.from_object(os.environ["APP_CONFIG"])

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

import api.routes
from api.api_spec import spec


with app.test_request_context():
#     # register all swagger documented functions here
    print(app.view_functions)
    for fn_name in app.view_functions:
        print("functions",fn_name)
        if fn_name == 'static':
            continue
        print(f"Loading swagger docs for function: {fn_name}")
        view_fn = app.view_functions[fn_name]
        spec.path(view=view_fn)