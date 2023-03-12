from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
cors = CORS(app, resources={r"/api/*": {"origins": "http://localhost:8080", "supports_credentials": True}})

@app.after_request
def after_request(response):
    # add some information to the header
    # we are going to do some credentials here
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:8080')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS,REDIRECT')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

@app.route('/login', methods=['POST'])
def login():
    print('h12')
    print(request)
    data = request.form
    print(f'data: {data}')
    username = data.get('username')
    password = data.get('password')

    print(f'user: {username} pass: {password}')
    # authenticate user
    authenticated = authenticate(username, password)

    if authenticated:
        # log user in
        log_in(username)
        response = jsonify({'message': 'login successful'})
        return response
    else:
        response = jsonify({'error': 'invalid username or password'}), 401
        return response

def authenticate(username, password):
    # login code goes here
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    return redirect(url_for('main.profile'))

def log_in(username):
    # log user in by setting session or other method
    pass

def log_out(username):
    # log user in by setting session or other method
    pass





if __name__ == '__main__':
    app.run()


