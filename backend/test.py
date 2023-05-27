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
salt = '5aP3v*4!1bN<x4i&3'
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
@test.route('/test/all', methods=['GET', 'POST', 'PUT'])
def signup_all():
    auth_headers = request.headers.get('Authorization', '').split()
    logging.debug(f'data:{auth_headers}')
    user_message = {
        'message': 'User not found.',
        'authenticated': False
    }
    user_message = {
        'message': 'User found.',
        'authenticated': True
    }
    try:
        token = auth_headers[1]
        logging.debug(f'token: {token}')
        data = jwt.decode(token, algorithms="HS256", key=current_app.config['SECRET_KEY'])
        logging.debug(f'decode: {data}')
        user = User.query.filter_by(email=data['user']).first()
        if not user:
            raise RuntimeError('User not found')
    except (jwt.ExpiredSignatureError, Exception) as e:
        logging.debug(f'ExpiredSignatureError:{e}')
        return jsonify(user_message), 401 # 401 is Unauthorized HTTP status code
    except (jwt.InvalidTokenError, Exception) as e:
        logging.debug(f'InvalidTokenError:{e}')
        return jsonify(user_message), 401
    res = make_response("Successful", 200)
    res.set_cookie(
        "JWT",
        value=token,
        expires=data['exp'],
        httponly=True,
        samesite="Strict")
    return res

@test.route('/test/alluser', methods=['GET', 'POST', 'PUT'])
def signup_alluser():
    logging.debug(f'data: {request.get_json()}')
    return ""
