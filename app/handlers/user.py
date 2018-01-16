# coding=utf8
from datetime import timedelta
import re
import base64
import shortuuid
from flask import Blueprint, session, render_template, url_for
from flask_login import login_required, current_user
from flask_restful import Resource, reqparse, abort, fields, marshal_with
from app import db, api, redis_cli, login_manager
from handlers.helper.oauth import OAuthSignIn
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


def key_user_oauth_state(provider_name, user):
    return 'oauth:state:{}:{}'.format(provider_name, user.id)


def set_user_oauth_state(provider_name):
    if current_user.is_authenticated:
        state = shortuuid.uuid()
        redis_cli.setex(key_user_oauth_state(provider_name, current_user), timedelta(minutes = 1), state)
        return state
    return ''


def get_user_oauth_state(provider_name):
    if current_user.is_authenticated:
        return redis_cli.get(key_user_oauth_state(provider_name, current_user))
    return ''


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


@user_endpoint.route('/oauth/<provider_name>', methods = ['GET'])
def login_by_oauth(provider_name):
    provider = OAuthSignIn.get_provider(provider_name)
    if provider:
        return provider.authorize(state = set_user_oauth_state(provider_name))
    else:
        return abort(404)


@user_endpoint.route('/oauth/github/callback', methods = ['GET'])
def login_by_github_callback():
    """Github OAuth 回调
    """
    code, state, info = OAuthSignIn.get_provider('github').callback()
    if code is None:
        return 'github 授权失败'

    if current_user.is_authenticated:
        if get_user_oauth_state('github') != state:
            return '错误的用户，授权失败'

        user = UserModel.query.filter_by(github_id = info.get('id')).first()
        if user is not None and user.id != current_user.id:
            return 'github 帐户已经被绑定过了'

        current_user.github_id = info.get('id')
        current_user.github_login = info.get('login')
        current_user.github_email = info.get('email')
        current_user.github_name = info.get('name')

        db.session.commit()

        return '绑定成功'

    else:
        user = UserModel.query.filter_by(github_id = info.get('id')).first()
        if user is None:
            user = UserModel(
                github_id = info.get('id'),
                github_login = info.get('login'),
                github_email = info.get('email'),
                github_name = info.get('name'),
            )
            db.session.add(user)
        login_user(user)

        return '登录成功'


@user_endpoint.route('/oauth/google/callback', methods = ['GET'])
def login_by_google_callback():
    """Github OAuth 回调
    """
    code, state, info = OAuthSignIn.get_provider('google').callback()
    if code is None:
        return 'google 授权失败'

    if current_user.is_authenticated:
        if get_user_oauth_state('google') != state:
            return '错误的用户，授权失败'

        user = UserModel.query.filter_by(google_id = info.get('id')).first()
        if user is not None and user.id != current_user.id:
            return ' google 帐户已经被绑定过了'

        current_user.google_id = info.get('id')
        current_user.google_email = info.get('email')
        current_user.google_name = info.get('name')

        db.session.commit()

        return '绑定成功'

    else:
        user = UserModel.query.filter_by(google_id = info.get('id')).first()
        if user is None:
            user = UserModel(
                google_id = info.get('id'),
                google_email = info.get('email'),
                google_name = info.get('name'),
            )
            db.session.add(user)
        login_user(user)

        return '登录成功'


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


@api.resource('/logout')
class Logout(Resource):
    def post(self):
        if current_user.is_authenticated:
            current_user.logout()
        return {}, 200


user_fields = {
    'id': fields.Integer,
    'first_name': fields.String(default = ''),
    'last_name': fields.String(default = ''),
    'nickname': fields.String(default = ''),
    'email': fields.String(default = ''),
    'mobile': fields.String(default = ''),
    'github_login': fields.String(default = ''),
    'github_name': fields.String(default = ''),
    'github_email': fields.String(default = ''),
    'google_name': fields.String(default = ''),
    'google_email': fields.String(default = ''),
    'last_login_at': fields.DateTime(dt_format = 'iso8601'),
    'created_at': fields.DateTime(dt_format = 'iso8601')
}


@api.resource('/profile')
class Profile(Resource):
    @marshal_with(user_fields)
    @login_required
    def get(self):
        return current_user


@login_manager.request_loader
def load_user_from_session(request):
    token = session.get('api_token')
    if token is not None:
        return UserModel.query.filter_by(api_token = token).first()
    return None
