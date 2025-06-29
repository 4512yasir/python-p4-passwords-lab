#!/usr/bin/env python3

from flask import Flask, request, session, jsonify, make_response
from flask_migrate import Migrate
from flask_restful import Resource, Api
from models import db, User
from config import app, db, api, bcrypt

migrate = Migrate(app, db)

# ==================== RESOURCES ====================

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if username and password:
            # Check if user already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                return {'error': 'Username already exists'}, 400

            # Create new user and hash password
            new_user = User(username=username)
            new_user.password_hash = password  # Password setter hashes automatically

            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id

            return new_user.to_dict(), 201

        return {'error': 'Missing username or password'}, 400


class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200

        return {'error': 'Invalid username or password'}, 401


class Logout(Resource):
    def delete(self):
        session['user_id'] = None
        return {}, 204


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if user_id:
            user = User.query.filter_by(id=user_id).first()
            return user.to_dict(), 200

        return {}, 204

# ==================== ROUTES ====================

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')

# ==================== SERVER ====================

if __name__ == '__main__':
    app.run(port=5555, debug=True)
