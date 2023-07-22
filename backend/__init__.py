from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mongoengine import MongoEngine
from flask_cors import CORS
import datetime
from settings import reads
# init SQLAlchemy so we can use it later in our models
# secret key is saved in file
db = SQLAlchemy()
Sessiondb = MongoEngine()
TodoListDB = MongoEngine()


def create_app():
    app = Flask(__name__)
    cors = CORS(app, resources={r"/api/*": {"origins": "http://localhost:8080", "supports_credentials": True}})
    app.config['SECRET_KEY'] = reads()
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(minutes=10) # define the life span of the token
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=1) # define the life span of the token
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://UserWriterReader:UserTest123@127.0.0.1:9556/UserData'
    app.config['MONGODB_SETTINGS_USERSESSIONS'] = {
        'db': 'UserSessions',
        'host': 'localhost',
        'port': 27017
    }
    app.config['MONGODB_SETTINGS_TODOLISTDATA'] = {
        'db': 'TodoListData',
        'host': 'localhost',
        'port': 27018
    }
    db.init_app(app)
    Sessiondb.init_app(app)
    TodoListDB.init_app(app)

    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .test import test as test_blueprint
    app.register_blueprint(test_blueprint)

    return app


if __name__ == '__main__':
    create_app()

