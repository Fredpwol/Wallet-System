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