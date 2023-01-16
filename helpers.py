# creates an extra function to check tokens for rightful access to content
# checks tokens and denies permission if the right token is not detected

from functools import wraps
import secrets
from flask import request, jsonify, json
import decimal

from models import User

def token_required(our_flask_function): # flask backend stuff, use pretty much any time a token will be required
    @wraps(our_flask_function)
    def decorated(*args, **kwargs): # token_required will continue to ask for decorated while the app is running
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token'].split(' ')[1] # headers is a dictionary, x-access-token is a key
        if not token:
            return jsonify({'message': 'Token is missing.'}), 401
        
        try:
            current_user_token = User.query.filter_by(token = token).first()
            # Goes to User class, asks for something, filters by token, and will find the first thing that comes up based on the token
            # Takes the token entered from line 17 and saves it to the variable
            # That variable is entered on line 22
            # It will search the db for a user with that token
            # The result is saved to current_user_token
            print(token)
            print(current_user_token)
        except:
            owner = User.query.filter_by(token = token).first()

            if token != owner.token and secrets.compare_digest(token, owner.token):
                return jsonify({'message': 'Token is invalid'})
        return our_flask_function(current_user_token, *args, **kwargs)
    return decorated

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            return str(obj)
        return super(JSONEncoder, self).default(obj)