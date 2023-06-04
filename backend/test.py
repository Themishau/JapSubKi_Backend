import jwt
import datetime
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, flash, current_app, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, SQL_Writer
from flask_cors import CORS
from . import db
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email
import logging
from functools import wraps
test = Blueprint('test', __name__)
db_sql = SQL_Writer()
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")

@test.after_request
def after_request(response):
    # add some information to the header
    # we are going to do some credentials here
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:8080')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

def token_required(f):
    @wraps(f)
    def _verify(*args, **kwargs):
        auth_headers = request.headers.get('Authorization', '').split()

        invalid_msg = {
            'message': 'Invalid token. Registeration and / or authentication required',
            'authenticated': False
        }
        expired_msg = {
            'error': 'Expired token. Reauthentication required.',
            'authenticated': False
        }
        logging.debug(f'test data:{auth_headers}')
        if len(auth_headers) != 2:
            return jsonify(invalid_msg), 401

        try:
            token = auth_headers[1]
            data = jwt.decode(token, algorithms="HS256", key=current_app.config['SECRET_KEY'])
            logging.debug(f'test encoded data:{data}')
            user = User.query.filter_by(email=data['user']).first()
            if not user:
                raise RuntimeError('User not found')
            return f(user, *args, **kwargs)
        except jwt.ExpiredSignatureError as e:
            logging.debug(f'test :{e}')
            return jsonify(expired_msg), 401  # 401 is Unauthorized HTTP status code
        except (jwt.InvalidTokenError, Exception) as e:
            logging.debug(f'test :{e}')
            return jsonify(invalid_msg), 403

    return _verify
@test.route('/test/', methods=['GET',])
@token_required
def signup_all(user):
    invalid_msg = {
        'error': 'Invalid token. Registeration and / or authentication required',
        'authenticated': False
    }

    return jsonify(''), 200


@test.route('/test/all', methods=['GET', 'POST', 'PUT'])
def signup_alluser():
    auth_headers = request.headers.get('Authorization', '').split()
    logging.debug(f'all data:{auth_headers}')
    invalid_msg = {
        'message': 'Invalid token. Registeration and / or authentication required',
        'authenticated': False
    }

    return jsonify(invalid_msg), 200
