from flask import Blueprint, render_template, redirect, url_for, request, jsonify, flash, current_app
import logging

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
test = Blueprint('test', __name__)

@test.after_request
def after_request(response):
    # add some information to the header
    # we are going to do some credentials here
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:8080')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response
@test.route('/test/all', methods=['GET'])
def signup():
    logging.debug(f'data: {request.get_json()}')
    return ""

