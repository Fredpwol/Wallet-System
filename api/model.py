
from api import db, bcrypt, app
from api.utils import CurrencyUtils
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired


class User(db.Model):
    """
    The User Model for representing users and their relations with other objects.
    A user have 3 possible roles the can be:
    1. Noob
    2. Elite
    3. Admin

    The Noob role is assigned to a user by default on registration but can be changed later by
    an admin.
    The main_currency attribute is used to create a default wallet for the user on registration.
    all other attributes are self explaintory.

    Attributes
    ----------
    username: sting

    email:string

    password:string

    role_id :int
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    wallet = db.relationship("Wallet", backref="owner", lazy="dynamic",
                             cascade="all, delete", passive_deletes=True)
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

    @property
    def serialize(self):
        """
        returns a JSON serializable representation of the User
        """
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "main_currency": self.main_currency,
            "role": self.role.name
        }

    def can(self, permissions):
        """
        Given a permission returns if the user can perform it based on the user role by
        perfoming some bitwise operations.

        Parameters
        ----------
        permissions: int
        """
        return self.role is not None and ((self.role.permission & permissions) == permissions)

    def verify_password(self, password):
        """
        Verifies a user password, with a supplied password

        Parameters
        ----------
        password: string
        """
        return bcrypt.check_password_hash(self.password, password)

    def generate_web_token(self, exp=2592000):
        """
        Generates a jwt for a user

        Parameters
        ----------
        exp: int, default=2592000
            Token expiry date.
        """
        serializer = Serializer(app.config["SECRET_KEY"], expires_in=exp)
        return serializer.dumps({"id": self.id}).decode("utf-8")

    @staticmethod
    def verify_web_token(token):
        """
        Verifies a token and returns a User object if the token is valid.

        Parameters
        ----------
        token: string
        """
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
    """
    Wallet object for performing transactions and storing cash.

    Attributes
    ----------
    currency: string

    user_id: int

    sent_transactions: queyset

    received_transactions: queryset
    """

    __tablename__ = "wallets"

    id = db.Column(db.Integer, primary_key=True)
    currency = db.Column(db.String(16), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(
        "users.id", ondelete="cascade"))
    sent_transactions = db.relationship(
        "Transaction", lazy="dynamic", foreign_keys="Transaction.sender")
    received_transaction = db.relationship(
        "Transaction", lazy="dynamic", foreign_keys="Transaction.receiver")

    @property
    def serialize(self):
        """
        returns a JSON serializable representation of a Wallet
        """
        return {
            "id": self.id,
            "currency": self.currency,
            "owner": self.owner.serialize,
            "balance": self.balance,
            "transactions": [tx.serialize for tx in self.sent_transactions.union(self.received_transaction).order_by(Transaction.at.desc())]
        }

    @property
    def balance(self):
        """
        returns a balance of the wallet from all transaction.
        """
        sent = [CurrencyUtils.convert_currency(
            tx.currency, self.currency, tx.amount) for tx in self.sent_transactions.filter_by(isapproved=True)]
        received = [CurrencyUtils.convert_currency(
            tx.currency, self.currency, tx.amount) for tx in self.received_transaction.filter_by(isapproved=True)]
        total_sent = 0.0
        total_received = 0.0
        print(sent, received)
        for tx in sent:
            total_sent += tx
        for tx in received:
            total_received += tx
        return total_received - total_sent

    def __repr__(self):
        return f"Wallet({self.currency}, {self.balance})"


class Transaction(db.Model):
    """
    Transactions that are done between wallets are stored by this model.
    """

    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True)
    at = db.Column(db.DateTime())
    sender = db.Column(db.Integer, db.ForeignKey(
        "wallets.id",  ondelete="SET NULL"))
    receiver = db.Column(db.Integer, db.ForeignKey(
        "wallets.id",  ondelete="SET NULL"))
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(16), nullable=False)
    isapproved = db.Column(db.Boolean, default=True)

    @property
    def serialize(self):
        """
        returns a JSON serializable representation of a Transaction
        """
        sender = None
        receiver = None
        if self.sender is not None:
            sender = Wallet.query.get(self.sender).owner.serialize
        if self.receiver is not None:
            receiver = Wallet.query.get(self.receiver).owner.serialize
        return {
            "id": self.id,
            "sender": sender,
            "receiver": receiver,
            "amount": self.amount,
            "currency": self.currency,
            "isapproved": self.isapproved
        }

    def __repr__(self):
        return f"Transaction({self.sender}, {self.receiver}, {self.amount})"


class Permissions:
    """
    A Permission class for holding class variables that represent permissions.

    Attributes
    ----------
    OWN_WALLET

    CREATE_WALLET

    CHANGE_CURRENCY

    CAN_WITHDRAW

    APRROVE_FUNDS

    CHANGE_ROLE 
    """
    OWN_WALLET = 0x01
    CREATE_WALLET = 0x02
    CHANGE_CURRENCY = 0x04
    CAN_WITHDRAW = 0x08
    APRROVE_FUNDS = 0x10
    CHANGE_ROLE = 0X20


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


class Role(db.Model):
    """
    The role used to give restrict user from some application functions.

    Attributes
    ----------
    name: str

    permissions: int

    default: bool, default=False

    users: queryset
    """
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), nullable=False, unique=True)
    permission = db.Column(db.Integer, nullable=False, unique=True)
    default = db.Column(db.Boolean, default=False)
    users = db.relationship("User", backref="role", lazy="dynamic")

    @staticmethod
    def initialize_roles():
        """
        This is used to initialize roles in a db, this should only be called once in your application
        """
        for role in roles:
            if Role.query.filter_by(name=role).first() is None:
                r = Role(
                    name=role, permission=roles[role][0], default=roles[role][1])
                db.session.add(r)
        db.session.commit()
