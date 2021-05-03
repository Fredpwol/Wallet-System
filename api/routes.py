import logging
import functools
import datetime
import os

from flask import request, jsonify, g
from flask_httpauth import HTTPBasicAuth
from api import app, db
from api.model import User, Role, Wallet, Permissions, Transaction, roles
from api.utils import CurrencyUtils

from api.api_spec import spec
from api.swagger import swagger_ui_blueprint, SWAGGER_URL

ok = "success"
error = "error"
unauthorized = "Unauthorized"


def permission_required(permission):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if g.user.can(permission):
                return func(*args, **kwargs)
            else:
                return jsonify(status=unauthorized, message="Permission denied!"), 401
        return wrapper
    return decorator


@app.route("/api/swagger.json")
def create_swagger_spec():
    return jsonify(spec.to_dict())


app.register_blueprint(swagger_ui_blueprint, url_prefix=SWAGGER_URL)


@app.before_first_request
def insert_roles():
    if len(Role.query.all()) != 3:
        Role.initialize_roles()


auth = HTTPBasicAuth()


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


@app.route("/")
def index():
    return "Hello welcome to your life!!"


@app.route("/users")
@auth.login_required
@permission_required(roles["Admin"][0])
def users():
    """
    ---
    get:
      summary: returns a list of users
      responses:
        '200':
          description: registration successful
          content:
            application/json:
                schema: Generated
      tags:
          - admin
          - user
    """
    return jsonify([user.serialize for user in User.query.all()])


@app.route("/users/<int:id>")
@auth.login_required
@permission_required(roles["Admin"][0])
def get_user(id):
    """
    ---
    get:
      parameters:
        - name: id
          in: path
          required: true
      summary: returns a users object from the id
      responses:
        '200':
          description:  fetched user
          content:
            application/json:
                schema: Generated
      tags:
          - admin
          - user
    """
    user = User.query.get(id)
    if user is None:
        return jsonify(status=error, message="User not Found!"), 400
    return jsonify(data=user.serialize, status=ok), 200


@app.route("/users/<int:id>/change-role", methods=["POST"])
@auth.login_required
@permission_required(Permissions.CHANGE_ROLE)
def change_user_role(id):
    """
    ---
    post:
      parameters:
        - name: id
          in: path
          required: true
      summary: change the role of a particular user
      responses:
        '200':
          description: change role successful
          content:
            application/json:
                schema: Generated
      tags:
          - admin
    """
    role = request.args.get("role")
    user = User.query.get(id)
    if user is None:
        return jsonify(status=error, message="User not Found!"), 400
    if not role:
        return jsonify(status=error, message="Please Input a Role Argument!"), 400
    if role.lower() in [r.lower() for r in roles.keys()]:
        user.role_id = Role.query.filter_by(name=role.capitalize()).first().id
    else:
        return jsonify(status=error, message="Please input a valid role"), 400
    db.session.commit()
    return jsonify(status=ok, message="User role changed sucessfully"), 200


@app.route("/users/<int:id>/change-maincurrency", methods=["POST"])
@auth.login_required
@permission_required(Permissions.CHANGE_CURRENCY)
def change_user_maincurrency(id):
    """
    ---
    post:
      parameters:
        - name: id
          in: path
          required: true
      summary: change the main currency a particular user
      responses:
        '200':
          description: success
          content:
            application/json:
                schema: Generated
      tags:
          - admin
    """
    currency = request.args.get("currency")
    user = User.query.get(id)
    if user is None:
        return jsonify(status=error, message="User not Found!"), 400
    if not currency:
        return jsonify(status=error, message="Please Input a currency"), 400
    if not CurrencyUtils.iscurrency_valid(currency):
        return jsonify(status=error, message="Please Enter a valid Currency code"), 400
    if not user.wallet.filter_by(currency=currency).first():
        new_wallet = Wallet(currency=currency, user_id=user.id)
        db.session.add(new_wallet)
        db.session.commit()

    user.main_currency = currency.lower()
    db.session.commit()
    return jsonify(status=ok, message="Maincurrency changed successfully"), 200


@app.route("/approve-transactions", methods=["POST"])
@auth.login_required
@permission_required(roles["Admin"][0])
def approve_transaction():
    """
    ---
    post:
      parameters:
        - name: tx
          in: query
          required: true
          description: id of a unapproved transactions
      summary: Approve a transaction from it's id
      responses:
        '200':
          description: success
          content:
            application/json:
                schema: TransactionResponse
      tags:
          - admin
    """
    try:
        ids = request.args['tx'].split(",")
        for _id in ids:
            tx = Transaction.query.filter_by(id=_id).first()
            if tx is None:
                return jsonify(status=error, message=f"Invalid Transaction id ({_id})"), 400
            tx.isapproved = True
            db.session.commit()
            return jsonify(status=ok), 200
    except KeyError:
        return jsonify(status=error, message="Missing keyword argument 'tx'"), 400


@app.route("/transactions", methods=["GET"])
@auth.login_required
@permission_required(roles["Admin"][0])
def transaction():
    """
    ---
    get:
      parameters:
        - name: only
          in: query
          required: true
          description: specify to filter out approved or unapproved transactions
      summary: get a list of all transactions
      responses:
        '200':
          description: success
          content:
            application/json:
                schema: TransactionResponse
      tags:
          - admin
    """
    only = request.args.get("only", None)
    transactions = Transaction.query.all()
    if bool(only):
        if not only in ["approved", "unapproved"]:
            return jsonify(), 400
        approved = True if only == "approved" else False
        transactions = Transaction.query.filter_by(isapproved=approved)
    return jsonify([tx.serialize for tx in transactions]), 200


@app.route("/users/register", methods=["POST"])
def register():
    """
    ---
    post:
      summary: register user
      requestBody:
        required: true
        content:
            application/json:
                schema: Register
      responses:
        '200':
          description: registration successful
          content:
            application/json:
              schema: AuthResponse
      tags:
          - user
    """
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
                    email=data["email"], currency=data["currency"].lower(), isadmin=isadmin)
    except Exception as e:
        logging.error(e)
        return jsonify(status=error, message=str(e)), 400

    db.session.add(user)
    db.session.commit()
    if not isadmin:
        default_wallet = Wallet(currency=data["currency"], user_id=user.id)
        db.session.add(default_wallet)
        db.session.commit()
        user.wallet.append(default_wallet)

    return jsonify(status=ok, token=user.generate_web_token(), user=user.serialize), 201


@app.route("/users/login", methods=["POST"])
def login():
    """
    ---
    post:
      summary: login user
      requestBody:
        required: true
        content:
            application/json:
                schema: Login
      responses:
        '200':
          description: registration successful
          content:
            application/json:
              schema: AuthResponse
      tags:
          - user
    """
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

    return jsonify(status=ok, token=user.generate_web_token(), user=user.serialize), 200


@app.route("/wallets")
@auth.login_required
@permission_required(Permissions.OWN_WALLET)
def get_wallet():
    """
    ---
    get:
      parameters:
        - name: currency
          in: query
          required: true
          description: filter out by currency
      summary: gets a list of all wallets
      responses:
        '200':
          description: success
          content:
            application/json:
                schema: WalletResponse
      tags:
          - wallet
    """
    try:
        currency = request.args.get("currency", None)
        if currency is not None:
            wallets = g.user.wallet.filter_by(currency=currency)
        else:
            wallets = g.user.wallet
        return jsonify(status=ok, data=[wallet.serialize for wallet in wallets]), 200
    except Exception as e:
        logging.error(e)
        return jsonify(status=error, message=str(e)), 400


@app.route("/wallets/<int:id>")
@auth.login_required
def get_wallet_by_id(id):
    """
    ---
    get:
      parameters:
        - name: id
          in: path
          required: true
      summary: get a wallet by id
      responses:
        '200':
          description: success
          content:
            application/json:
                schema: WalletResponse
      tags:
          - wallet
    """
    try:
        wallet = g.user.wallet.filter_by(id=id).first()
        if wallet:
            return jsonify(status=ok, data=wallet.serialize), 200
        else:
            return jsonify(status=error, message=f"User does not own a wallet with the id ({id})")
    except Exception as e:
        logging.error(e)
        return jsonify(status=error, message=str(e)), 400


@app.route("/wallet/create", methods=["POST"])
@auth.login_required
@permission_required(Permissions.CREATE_WALLET)
def create_wallet():
    """
    ---
    post:
      summary: create a wallet, this is only available for Elite users
      responses:
        '201':
          description: created
          content:
            application/json:
                schema: WalletResponse
      tags:
          - wallet
    """
    try:
        data = request.get_json()
        wallet = Wallet(currency=data["currency"], user_id=g.user.id)
        db.session.add(wallet)
        db.session.commit()
        user.wallet.append(wallet)
        return jsonify(status=ok, data=wallet.serialize), 201
    except Exception as e:
        logging.error(e)
        return jsonify(status=error, message=str(e)), 400


@app.route("/fund", methods=["POST"])
@auth.login_required
def fund_wallet():
    """
    ---
    post:
      summary: fund a particular wallet
      description: sends funds to a particular user given the user id the amount will be 
        removed from the wallet with the respective currency, if not it falls to the default wallet.
        if the sender is admin no money will be deducted from any wallet else an amount will be deducted 
        from the sender wallet with the respective currency. so that means that admin can geenrate cash while
        other users can perform transactions between wallets.
      requestBody:
        required: true
        content:
            application/json:
                schema: Fund
      responses:
        '200':
          description: success
          content:
            application/json:
                schema: TransactionResponse
      tags:
          - user
          - admin
    """
    try:
        required = ["currency", "amount", "receiver"]
        data = request.get_json()
        if not all([rq in data.keys() for rq in required]):
            return jsonify(status=error, message="Missing Required JSON Field!")
        amount = data["amount"]
        currency = data["currency"]
        receiver_id = data["receiver"]
        if not CurrencyUtils.iscurrency_valid(currency):
            return jsonify(status=error, message="Please Enter a valid Currency code"), 400
        if g.user.role.name != "Admin":
            sender_wallet = g.user.wallet.filter_by(currency=currency).first()

            if sender_wallet is None:
                sender_wallet = g.user.wallet.filter_by(
                    currency=g.user.main_currency)
                if CurrencyUtils.convert_currency(sender_wallet.currency.upper(), currency.upper(), sender_wallet.balance) < amount:
                    return jsonify(status=error, message="Insufficient fund!"), 403
                amount = CurrencyUtils.convert_currency(
                    sender_wallet.currency.upper(), currency.upper(), amount)
            else:
                if sender_wallet.balance < amount:
                    return jsonify(status=error, message="Insufficient fund!"), 403

        receiver = User.query.filter_by(id=receiver_id).first()
        if not receiver:
            return jsonify(status=error, message=f"Sorry User with id {receiver_id} does not exsits!"), 400
        if receiver.role.name == "Admin":
            return jsonify(status=unauthorized, message="Sorry Admin account can't be funded!"), 403
        receiver_wallet = receiver.wallet.filter_by(currency=currency).first()

        if receiver_wallet is None:
            if receiver.role.name == "Elite":
                new_wallet = Wallet(currency=currency, user_id=receiver.id)
                db.session.add(new_wallet)
                db.session.commit()
                receiver_wallet = new_wallet
            elif receiver.role.name == "Noob":
                receiver_wallet = receiver.wallet.filter_by(
                    currency=receiver.main_currency.lower()).first()
        if g.user.role.name == "Admin":
            tx = Transaction(receiver=receiver_wallet.id, sender=None,
                             amount=amount, currency=currency, at=datetime.datetime.utcnow())
        else:
            tx = Transaction(receiver=receiver_wallet.id, sender=sender_wallet.id,
                             amount=amount, currency=currency, at=datetime.datetime.utcnow())

        if receiver.role.name == "Noob":
            tx.isapproved = False

        db.session.add(tx)
        db.session.commit()

        return jsonify(status=ok, data=tx.serialize), 200

    except SyntaxError as e:
        logging.error(e)
        return jsonify(status=error, message=str(e)), 400


@app.route("/withdraw", methods=["POST"])
@auth.login_required
@permission_required(Permissions.CAN_WITHDRAW)
def withdraw():
    """
    ---
    post:
      summary: Withdraw from a particular wallet 
      description: withdraws money from a user from a wallet with the respective suplied currency. if an Elite class user withdraws
        the amount will instanstly be deducted from the wallet with the respective currency if the wallet does not exists or has isufficient
        funds it falls back and withdraws the equivalent of that in the main currency.
      requestBody:
        required: true
        content:
            application/json:
                schema: Withdraw
      responses:
        '200':
          description: success
          content:
            application/json:
                schema: NormalResponse
      tags:
          - user
    """
    data = request.get_json()
    required = ["currency", "amount"]
    if not all([rq in data for rq in required]):
        return jsonify(status=error, message="Missing required JSON field!"), 400
    currency = data["currency"]
    amount = data["amount"]
    wallet = g.user.wallet.filter_by(currency=currency).first()
    if wallet is None or (g.user.role.name == "Elite" and (bool(wallet) and wallet.balance < amount)):
        wallet = g.user.wallet.filter_by(
            currency=g.user.main_currency.lower()).first()
        amount = CurrencyUtils.convert_currency(
            currency, wallet.currency, amount)
    if wallet.balance < amount:
        return jsonify(status=error, message="Insufficent Funds!"), 400
    isapproved = True if g.user.role.name != "Noob" else False
    tx = Transaction(sender=wallet.id, receiver=None, at=datetime.datetime.utcnow(),
                     amount=amount, currency=wallet.currency, isapproved=isapproved)
    db.session.add(tx)
    db.session.commit()
    return jsonify(status=ok, message="Transaction successful."), 200
