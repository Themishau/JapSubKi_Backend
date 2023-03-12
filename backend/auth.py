import jwt
import datetime
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, flash
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

@auth.after_request
def after_request(response):
    # add some information to the header
    # we are going to do some credentials here
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:8080')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

@auth.route('/login', methods=['POST'])
def login():
    logging.debug(f'data: {request}')
    logging.debug(f'data: {request.form}')
    username = request.form.get('username')
    password = request.form.get('password')
    password += salt

    user = User.query.filter_by(email=username).first() # if this returns a user, then the email already exists in database
    logging.debug(user)
    if not user: # if a user is not found, we want to redirect back to signin page so user can try again
        return redirect(url_for('auth.signin'))
    logging.debug(f'is available: user: {username} pass: {password}')
    # authenticate user
    authenticated = authenticate(username, password)

    if authenticated:
        # log user in
        log_in()
        token = jwt.encode({'user' : username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, username + salt)
        response = jsonify({'token': token, 'user' : username, 'message': 'login successful'})
        return response
    else:
        response = jsonify({'error': 'invalid username or password'}), 401
        return response

@auth.route('/signup')
def signup():
    return redirect(url_for('auth.signup'))

@auth.route('/user', methods=['GET'])
def get_user():
    logging.debug(f'data: {request}')
    username = request.form.get('username')
    logging.debug(f'user: {username}')
    token = jwt.encode({'user' : 'test', 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, 'test' + salt)
    logging.debug(f'token: {token}')
    response = jsonify({'token': token, 'user' : username, 'message': 'login successful'})
    return response

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
    user = User.query.filter_by(email=username).first() # if this returns a user, then the email already exists in database
    logging.debug(user)
    if user: # if a user is found, we want to redirect back to signup page so user can try again
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

@auth.route('/logout')
def authenticate(username, password):
    # login code goes here
    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=username).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    return redirect(url_for('main.profile'))

@auth.route('/login')
def log_in():
    # log user in by setting session or other method
    pass

@auth.route('/logout')
def log_out(username):
    # log user in by setting session or other method
    pass

