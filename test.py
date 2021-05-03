
import json
import os
import unittest
from dotenv import load_dotenv
load_dotenv()

from api import app, db
from api.model import Role
from api.routes import ok
from requests.auth import _basic_auth_str



basedir = os.path.abspath(os.path.dirname(__file__))


class TestRestApi(unittest.TestCase):
    def setUp(self):
        app.config.from_object("api.config.TestingConfig")
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
            os.path.join(basedir, 'test.db')
        self.app = app.test_client()
        self.noob_payload = json.dumps({
            "username": "sam",
            "password": "123456",
            "currency": "ngn",
            "email": "sam@gmail.com"
        })
        self.noob2_payload = json.dumps({
            "username": "mike",
            "password": "123456",
            "currency": "usd",
            "email": "mike@gmail.com"
        })
        self.admin_payload = json.dumps({
            "username": "superuser",
            "password": "123456",
            "currency": "eur",
            "email": "admin@gmail.com",
            "isadmin": True
        })
        db.create_all()
        Role.initialize_roles()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def register_user(self, user):
        res = self.app.post(
            "/users/register", headers={"Content-Type": "application/json"}, data=user)
        self.assertEqual(201, res.status_code)
        self.assertEqual(res.json["status"], ok)
        return res.json["token"], res.json["user"]

    def login_user(self, user):
        res = self.app.post(
            "/users/login", headers={"Content-Type": "application/json"}, data=user)
        self.assertEqual(200, res.status_code)
        self.assertEqual(res.json["status"], ok)

    def test_user_authentication(self):
        self.register_user(self.noob_payload)
        self.register_user(self.noob2_payload)
        self.register_user(self.admin_payload)
        self.login_user(self.noob_payload)
        self.login_user(self.noob2_payload)
        self.login_user(self.admin_payload)

    def test_permissions(self):
        admin_token, _ = self.register_user(self.admin_payload)
        noob_token, _ = self.register_user(self.noob_payload)
        headers = {
            'Authorization': _basic_auth_str(admin_token, "no-password"),
        }
        admin_request = self.app.get(
            "/users", headers=headers)
        self.assertEqual(admin_request.status_code, 200)

        noob_request = self.app.get(
            "/users", headers={"Authorization": _basic_auth_str(noob_token, "pass")})
        self.assertEqual(noob_request.status_code, 401)

    def test_sendfunds(self):
        admin_token, _ = self.register_user(self.admin_payload)
        noob_token, noob = self.register_user(self.noob_payload)
        tx = json.dumps({
            "currency": "ngn",
            "amount": 500,
            "receiver": noob["id"]
        })
        fund = self.app.post("/fund", headers={"Authorization": _basic_auth_str(
            admin_token, "pass"), "Content-Type": "application/json"}, data=tx)
        self.assertEqual(fund.status_code, 200)
        self.assertEqual(fund.json["data"]["amount"], 500)
        self.assertEqual(fund.json["data"]["currency"], "ngn")
        self.assertEqual(fund.json["data"]["isapproved"], False)

    def test_withdraw(self):
        admin_token, _ = self.register_user(self.admin_payload)
        noob_token, noob = self.register_user(self.noob_payload)
        tx = json.dumps({
            "currency": "ngn",
            "amount": 500,
            "receiver": noob["id"]
        })
        fund = self.app.post("/fund", headers={"Authorization": _basic_auth_str(admin_token, "pass"),
                                               "Content-Type": "application/json"}, data=tx)
        tx_id = fund.json["data"]["id"]
        approve = self.app.post("/approve-transactions?tx={}".format(tx_id), headers={"Authorization": _basic_auth_str(admin_token, "pass"),
                                                                                      "Content-Type": "application/json"})
        valid_withdraw = self.app.post("/withdraw", headers={"Authorization": _basic_auth_str(noob_token, "pass"),
                                                             "Content-Type": "application/json"}, data=json.dumps({"currency": "ngn", "amount": 200}))
        self.assertEqual(valid_withdraw.status_code, 200)
        invalid_withdraw = self.app.post("/withdraw", headers={"Authorization": _basic_auth_str(noob_token, "pass"),
                                                             "Content-Type": "application/json"}, data=json.dumps({"currency": "ngn", "amount": 1000}))
        
        self.assertEqual(invalid_withdraw.json["message"].lower(), "Insufficent Funds!".lower())

    def test_change_role(self):
        admin_token, _ = self.register_user(self.admin_payload)
        noob_token, noob = self.register_user(self.noob_payload)
        headers={"Authorization": _basic_auth_str(admin_token, "pass"), "Content-Type": "application/json"}
        req = self.app.post("/users/{}/change-role?role={}".format(noob["id"], "elite"), headers=headers)
        self.assertEqual(req.status_code, 200)
        user = self.app.get("/users/{}".format(noob["id"]), headers=headers).json["data"]["role"]
        self.assertEqual(user.lower(), "elite")


    def test_change_currency(self):
        admin_token, _ = self.register_user(self.admin_payload)
        noob_token, noob = self.register_user(self.noob_payload)
        headers={"Authorization": _basic_auth_str(admin_token, "pass"), "Content-Type": "application/json"}
        req = self.app.post("/users/{}/change-maincurrency?currency={}".format(noob["id"], "usd"), headers=headers)
        self.assertEqual(req.status_code, 200)
        user = self.app.get("/users/{}".format(noob["id"]), headers=headers).json["data"]["main_currency"]
        self.assertEqual(user.lower(), "usd")
  
  
    def test_approve_tx(self):
        admin_token, _ = self.register_user(self.admin_payload)
        noob_token, noob = self.register_user(self.noob_payload)
        tx = json.dumps({
            "currency": "ngn",
            "amount": 500,
            "receiver": noob["id"]
        })
        fund = self.app.post("/fund", headers={"Authorization": _basic_auth_str(admin_token, "pass"),
                                               "Content-Type": "application/json"}, data=tx)
        tx_id = fund.json["data"]["id"]
        approve = self.app.post("/approve-transactions?tx={}".format(tx_id), headers={"Authorization": _basic_auth_str(admin_token, "pass"), 
                    "Content-Type": "application/json"})
        self.assertEqual(approve.status_code, 200)


if __name__ == "__main__":
    unittest.main()
