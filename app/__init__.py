from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from flask import Flask

from . import config
import os

app = Flask(__name__)
environment = os.getenv('FLASK_ENV', 'production')
app.config.from_object(config.configuration[environment])
db = SQLAlchemy(app)

from . import models
from app.models import User, Budget, Expense, Income, MiniExpense

migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)

from . import views
