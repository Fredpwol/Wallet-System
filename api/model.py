
from api import db, bcrypt, app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    wallet = db.relationship("Wallet", backref="owner", lazy="dynamic", cascade="all, delete", passive_deletes=True)
    main_currency = db.Column(db.String(16), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"))

    def __init__(self, username, email, password, currency, isadmin=False):
        self.username = username
        self.email = email
        self.password = bcrypt.generate_password_hash(password).decode("utf8")
        self.main_currency = currency
        if self.role is None:
            if isadmin:
                self.role = Role.query.filter_by(name="Admin").first()
            else:
                self.role = Role.query.filter_by(default=True).first()

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def generate_web_token(self, exp=43200):
        serializer = Serializer(app.config["SECRET_KEY"], expires_in=exp)
        return serializer.dumps({"id": self.id}).decode("utf-8")

    @staticmethod
    def verify_web_token(token):
        serializer = Serializer(app.config['SECRET_KEY'])
        try:
            data = serializer.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = User.query.get(data['id'])
        return user

    def __repr__(self):
        return f"User({self.username})"


class Wallet(db.Model):

    __tablename__ = "wallets"

    id = db.Column(db.Integer, primary_key=True)
    currency = db.Column(db.String(16), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="cascade"))
    transactions = db.relationship(
        "Transaction", backref="wallet", lazy="dynamic", cascade="all, delete")

    @property
    def balance(self):
        sent = Transaction.query.filter_by(sender=self.owner.id)
        received = Transaction.query.filter_by(recever=self.owner.id)
        total_sent = 0.0
        total_recieved = 0.0
        for tx in sent:
            total_sent += tx.amount
        for tx in received:
            total_recieved += tx.amount
        return total_recieved - total_sent

    def __repr__(self):
        return f"Wallet({self.currency}, {self.balance})"


class Transaction(db.Model):

    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    reciver = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(16), nullable=False)
    wallet_id = db.Column(db.Integer, db.ForeignKey("wallets.id", ondelete="cascade"))
    isapproved = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"Transaction({self.sender}, {self.recever}, {self.amount})"


class Permissions:
    OWN_WALLET = 0x01
    CREATE_WALLET = 0x02
    CHANGE_CURRENCY = 0x04
    CAN_WITHDRAW = 0x08
    APRROVE_FUNDS = 0x10
    CHANGE_ROLE = 0X20


class Role(db.Model):

    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), nullable=False)
    permission = db.Column(db.Integer, nullable=False)
    default = db.Column(db.Boolean, default=False)
    users = db.relationship("User", backref="role")

    @staticmethod
    def initialize_roles():
        roles = {
            "Noob": [
                (Permissions.OWN_WALLET | Permissions.CAN_WITHDRAW),
                True
            ],
            "Elite": [
                (Permissions.OWN_WALLET | Permissions.CAN_WITHDRAW |
                 Permissions.CREATE_WALLET),
                False
            ],
            "Admin": [
                (Permissions.APRROVE_FUNDS |
                 Permissions.CHANGE_CURRENCY | Permissions.CHANGE_ROLE),
                False
            ]
        }

        for role in roles:
            if Role.query.filter_by(name=role) is None:
                r = Role(
                    name=role, permission=roles[role][0], default=roles[role][1])
                db.session.add(r)
        db.session.commit()