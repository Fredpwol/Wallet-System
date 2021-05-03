from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
from marshmallow import Schema, fields

# Create an APISpec
spec = APISpec(
    title="Wallet System",
    version="1.0.0",
    openapi_version="3.0.2",
    plugins=[FlaskPlugin(), MarshmallowPlugin()],
)

# Define schemas


UserFields = Schema.from_dict({"id": fields.Int(), "username": fields.String(),
                               "email": fields.String(), "main_currency": fields.String(), "role": fields.String()})

TransactionFields = Schema.from_dict({"id": fields.Int(), "sender": fields.Int(), "receiver": fields.Int(),
                                      "amount": fields.Float(), "currency": fields.String(), "isapproved": fields.Boolean()}
                                     )
class WalletSchema(Schema):
    id = fields.Int()
    currency = fields.String()
    owner = fields.Nested(UserFields)
    balance = fields.Float()
    transactions = fields.Nested(TransactionFields)


class LoginSchema(Schema):
    username = fields.String(description="User username.", required=True)
    password = fields.String(description="User password", required=True)


class RegisterSchema(Schema):
    username = fields.String(description="User username.", required=True)
    password = fields.String(description="User password", required=True)
    currency = fields.String(description="User main currency", required=True)
    email = fields.String(description="User email", required=True)
    isadmin = fields.Boolean(
        description="ADMIN role assigned", required=False, default=False)


class AuthResponseSchema(Schema):
    status = fields.String()
    token = fields.String()
    user = fields.Nested(UserFields)


class NormalResponseSchema(Schema):
    status = fields.String(default="success")
    message = fields.String()


class FundSchema(Schema):
    currency = fields.String()
    amount = fields.Float()
    receiver = fields.Int()


class WithdrawSchema(Schema):
    currency = fields.String()
    amount = fields.Float()


class UserResponseSchema(Schema):
    status = fields.String()
    user = fields.Nested(UserFields)


# class DataResponseSchema(Schema):
#     status = fields.String(default="success")
#     data = fields.String


class TransactionSchema(Schema):
    status = fields.String(default="success")
    data = fields.Nested(TransactionFields)


# register schemas with spec
spec.components.schema("Login", schema=LoginSchema)
spec.components.schema("Register", schema=RegisterSchema)
spec.components.schema("AuthResponse", schema=AuthResponseSchema)
spec.components.schema("NormalResponse", schema=NormalResponseSchema)
spec.components.schema("Fund", schema=FundSchema)
spec.components.schema("Withdraw", schema=WithdrawSchema)
spec.components.schema("UserResponse", schema=UserResponseSchema)
spec.components.schema("TransactionResponse", schema=TransactionSchema)
spec.components.schema("WalletResponse", schema=WalletSchema)

# add swagger tags that are used for endpoint annotation
tags = [
    {'name': 'user',
             'description': 'For performing user tasks'
     },
    {'name': 'wallet',
             'description': 'Intefacing with wallet.'
     },
    {
        "name": "admin",
        "description": "Admin only endpoints"
    }
]

for tag in tags:
    print(f"Adding tag: {tag['name']}")
    spec.tag(tag)
