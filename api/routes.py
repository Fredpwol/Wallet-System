import logging

from flask import request, jsonify, g
from flask_httpauth import HTTPBasicAuth
from api import app, db
from api.model import User, Role, Wallet
from api.utils import CurrencyUtils


@app.before_first_request
def insert_roles():
    if len(Role.query.all()) != 3:
        Role.initialize_roles()


auth = HTTPBasicAuth()

ok = "success"
error = "error"


@auth.verify_password
def verify_password(username_or_token, password):
    if not (username_or_token or password):
        return False
    user = User.verify_web_token(username_or_token)
    if not user:
        user = User.query.filter_by(username=username_or_token).first()
        if (not user) or (not user.validate_password(password)):
            return False
    g.user = user
    return True


@app.route("/user/register", methods=["POST"])
def register():
    data = request.get_json()
    required_keys = ["username", "password", "email", "currency"]
    if not all([rqkey in data for rqkey in required_keys]):
        return jsonify(status=error, message="Sorry missing JSON field!"), 400
    try:
        if User.query.filter_by(username=data["username"]).first() is not None:
            return jsonify(status=error, message="Sorry username already Taken!"), 400
        if User.query.filter_by(username=data["username"]).first() is not None:
            return jsonify(status=error, message="Sorry username already Taken!"), 400

        if not CurrencyUtils.iscurrency_valid(data["currency"]):
            return jsonify(sattus=error, message="Sorry Please Enter a Valid currency code!"), 400
        isadmin = data.get("isadmin", False)
        user = User(username=data["username"], password=data["password"],
                    email=data["email"], currency=data["currency"], isadmin=isadmin)
    except Exception as e:
        logging.error(e)
        return jsonify(status=error, message=str(e)), 400

    db.session.add(user)
    db.session.commit()
    default_wallet = Wallet(currency=data["currency"], user_id=user.id)
    db.session.add(default_wallet)
    db.session.commit()
    user.wallet.append(default_wallet)

    return jsonify(status=ok, token=user.generate_web_token()), 201


@app.route("/user/login", methods=["POST"])
def login():
    data = request.get_json()
    required_keys = ["username", "password"]
    if not all([rqkey in data for rqkey in required_keys]):
        return jsonify(status=error, message="Sorry missing JSON field!"), 400
    try:
        user = User.query.filter_by(username=data["username"]).first()
        if user is None or not user.verify_password(data["password"]):
            return jsonify(status=error, message="Invalid username or password")
    except Exception as e:
        logging.error(e)
        return jsonify(status=error, message=str(e)), 400

    return jsonify(status=ok, token=user.generate_web_token(), user=user.serialize), 201


@app.route("/wallets")
@auth.login_required
def get_wallet():
    try:
        return jsonify([wallet.serialize for wallet in g.user.wallet])
    except Exception as e:
        logging.error(e)
        return jsonify(status=error, message=str(e)), 400
