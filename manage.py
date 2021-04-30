import os

from dotenv import load_dotenv
load_dotenv()


from flask_script import Manager
from flask_migrate import MigrateCommand, Migrate
from api import app, db



manager = Manager(app)
Migrate(app=app, db=db)
manager.add_command("db", MigrateCommand)

if __name__ == "__main__":
    manager.run()