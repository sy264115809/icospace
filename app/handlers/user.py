# coding=utf8
from datetime import timedelta
import re
import base64
import shortuuid
from flask import Blueprint, session, current_app, render_template, url_for
from flask_login import login_required
from flask_restful import Resource, reqparse, abort
from app import db, api, redis_cli, login_manager
from app.models.user import User as UserModel
from app.utils.mail import send_email

duplicate_pattern = re.compile("Duplicate entry '(?P<value>.+)' for key '(?P<filed>.+)'")

user_endpoint = Blueprint('user', __name__, url_prefix = '/users')


def key_activate_email_code(email):
    return 'activate:email:{}'.format(email)


def send_activate_email(email):
    key = key_activate_email_code(email)
    activate_code = shortuuid.uuid()

    redis_cli.setex(key, timedelta(days = 1), activate_code)
    activate_url = url_for('user.activate_email',
                           e = base64.urlsafe_b64encode(email),
                           c = activate_code,
                           _external = True)
    send_email(email, u'邮箱激活', 'activate_email.html', activate_url = activate_url)


def get_user_by_email(email):
    user = UserModel.query.filter_by(email = email).first()
    if user is None:
        abort(404, message = 'user is not exists')

    return user


def login_user(user):
    session['api_token'] = user.login()


@user_endpoint.route('/email/active', methods = ['GET'])
def activate_email():
    parser = reqparse.RequestParser()
    parser.add_argument('e', location = 'args', type = str, required = True)
    parser.add_argument('c', location = 'args', type = str, required = True)
    args = parser.parse_args()

    try:
        email = base64.urlsafe_b64decode(args['e'])
    except Exception as e:
        return '无效链接'

    user = UserModel.query.filter_by(email = email).first()
    if user is None:
        return '无效链接'

    if user.activated:
        return '用户已激活'

    activated = args['c'] == redis_cli.get(key_activate_email_code(email))

    if activated:
        user.activated = True
        db.session.commit()

    return render_template('activate_email.html', email = email, activated = activated)


@api.resource('/signup')
class Signup(Resource):

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', required = True)
        parser.add_argument('password', required = True)
        parser.add_argument('first_name')
        parser.add_argument('last_name')
        args = parser.parse_args()

        user = UserModel(
            email = args['email'],
            password = args['password'],
            first_name = args['first_name'],
            last_name = args['last_name']
        )
        db.session.add(user)
        try:
            db.session.commit()
        except Exception as e:
            match = duplicate_pattern.search(e.message)
            if match:
                db.session.rollback()

                groups = {
                    'value': match.group('value'),
                    'filed': match.group('filed')
                }
                abort(409, message = "duplicate value '{value}' for key '{filed}'".format(**groups), **groups)

        send_activate_email(user.email)

        return {'id': user.id}, 201


@api.resource('/users/email/active/resend')
class ResendActiveEmil(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', required = True)
        args = parser.parse_args()

        user = get_user_by_email(args['email'])
        if user.activated:
            abort(403, message = 'user is already activated')

        send_activate_email(user.email)
        return {}, 200


@api.resource('/login')
class Login(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', required = True)
        parser.add_argument('password', required = True)
        args = parser.parse_args()

        user = get_user_by_email(args['email'])

        if args['email'] != user.email or not user.check_password(args['password']):
            abort(401)

        if not user.activated:
            abort(403, message = "user is not activated")

        login_user(user)
        return {}, 200


@login_manager.request_loader
def load_user_from_session(request):
    token = session.get('api_token')
    if token is not None:
        return UserModel.query.filter_by(api_token = token).first()
    return None
