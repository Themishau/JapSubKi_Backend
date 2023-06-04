import jwt
import datetime
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, flash, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, SQL_Writer
from flask_cors import CORS
from . import db
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email
import logging
from functools import wraps

auth = Blueprint('auth', __name__)
db_sql = SQL_Writer()
salt = '5aP3v*4!1bN<x4i&3'
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")


def token_required(f):
    @wraps(f)
    def _verify(*args, **kwargs):
        auth_headers = request.headers.get('Authorization', '').split()

        invalid_msg = {
            'message': 'Invalid token. Registeration and / or authentication required',
            'authenticated': False
        }
        expired_msg = {
            'message': 'Expired token. Reauthentication required.',
            'authenticated': False
        }

        if len(auth_headers) != 2:
            return jsonify(invalid_msg), 401

        try:
            token = auth_headers[1]
            data = jwt.decode(token, algorithms="HS256", key=current_app.config['SECRET_KEY'])
            user = User.query.filter_by(email=data['user']).first()
            if not user:
                raise RuntimeError('User not found')
            return f(user, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify(expired_msg), 401  # 401 is Unauthorized HTTP status code
        except (jwt.InvalidTokenError, Exception) as e:
            print(e)
            return jsonify(invalid_msg), 401

    return _verify

@auth.route('/auth/checkUser', methods=['GET', 'POST'])
@token_required
def checkUser():
    return jsonify('OK'), 202

@auth.after_request
def after_request(response):
    # add some information to the header
    # we are going to do some credentials here
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:8080')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response


@auth.route('/auth/signin', methods=['POST', ])
def login():
    logging.debug(f'data: {request.get_json()}')
    username = request.get_json().get('username')
    password = request.get_json().get('password')
    password += salt

    user = User.query.filter_by(
        email=username).first()  # if this returns a user, then the email already exists in database
    logging.debug(user)
    if not user:  # if a user is not found, we want to redirect back to signin page so user can try again
        return redirect(url_for('auth.signin'))
    logging.debug(f'is available: user: {username} pass: {password}')
    # authenticate user
    authenticated = authenticate(username, password)
    logging.debug(f'authenticated: {authenticated} ')
    if authenticated:
        # log user in
        accessToken = jwt.encode(
            {'user': username, 'exp': datetime.datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']},
            key=current_app.config['SECRET_KEY'])
        refreshToken = jwt.encode(
            {'user': username, 'exp': datetime.datetime.utcnow() + current_app.config['JWT_REFRESH_TOKEN_EXPIRES']},
            key=current_app.config['SECRET_KEY'])
        response = jsonify({'accessToken': accessToken, 'refreshToken': refreshToken, 'user': username, 'message': 'login successful'})
        return response
    else:
        response = jsonify({'error': 'invalid username or password'}), 401
        return response


@auth.route('/auth/refreshtoken', methods=['POST', ])
def getRefreshToken():
    # logging.debug(f'refresh data1: {request}')
    logging.debug(f'refresh data: {request.get_json()}')

    auth_headers = request.headers.get('Authorization', '').split()
    logging.debug(f'data:{auth_headers}')

    user_message = {
        'message': 'User not found.',
        'authenticated': False
    }

    try:
        token = auth_headers[1]
        logging.debug(f'token: {token}')
        data = jwt.decode(token, algorithms="HS256", key=current_app.config['SECRET_KEY'])
        logging.debug(f'decode: {data}')
        user = User.query.filter_by(email=data['user']).first()
        if not user:
            raise RuntimeError('User not found')
        accessToken = jwt.encode(
            {'user': user, 'exp': datetime.datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']},
            key=current_app.config['SECRET_KEY'])
        refreshToken = jwt.encode(
            {'user': user, 'exp': datetime.datetime.utcnow() + current_app.config['JWT_REFRESH_TOKEN_EXPIRES']},
            key=current_app.config['SECRET_KEY'])
        response = jsonify({'accessToken': accessToken, 'refreshToken': refreshToken, 'user': user, 'exp': datetime.datetime.utcnow() + current_app.config['JWT_REFRESH_TOKEN_EXPIRES'], 'message': 'login successful'})
        return response
    except (jwt.ExpiredSignatureError, Exception) as e:
        logging.debug(f'ExpiredSignatureError:{e}')
        return jsonify(user_message), 403 # 401 is Unauthorized HTTP status code
    except (jwt.InvalidTokenError, Exception) as e:
        logging.debug(f'InvalidTokenError:{e}')
        return jsonify(user_message), 403





@auth.route('/signup')
def signup():
    return redirect(url_for('auth.signup'))


# @auth.route('/user', methods=['GET'])
# @token_required
# def get_user():
#     logging.debug(f'get_user data: {request}')
#     username = request.form.get('username')
#     logging.debug(f'user: {username}')
#     token = jwt.encode({'user': 'test', 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
#                        'test' + salt)
#     logging.debug(f'token: {token}')
#     response = jsonify({'token': token, 'user': username, 'message': 'login successful'})
#     return response


@auth.route('/signup', methods=['POST'])
def signup_post():
    # code to validate and add user to database goes here
    # username = StringField("username", validators=[DataRequired()])
    # password = PasswordField("password", validators=[DataRequired()])
    username = request.form.get('username')
    password = request.form.get('password')
    password += salt
    logging.debug(f'user: {username} pass: {password}')
    db_sql.testConnection()
    user = User.query.filter_by(
        email=username).first()  # if this returns a user, then the email already exists in database
    logging.debug(user)
    if user:  # if a user is found, we want to redirect back to signup page so user can try again
        return redirect(url_for('auth.signup'))

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(email=username, password=generate_password_hash(password, method='sha256'))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()
    #
    # return redirect(location=url_for('auth.login'))
    response = jsonify({'message': 'signup successful'})
    return response


def authenticate(username, password):
    # login code goes here
    username = username
    password = password
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=username).first()
    logging.debug(f'user: {user} pass: {password}')
    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        # return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page
        return False
    # if the above check passes, then we know the user has the right credentials
    # return redirect(url_for('main.profile'))
    return True
