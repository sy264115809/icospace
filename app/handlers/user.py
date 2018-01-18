# coding=utf8
from datetime import timedelta
import re
import base64
import shortuuid
from flask import Blueprint, session, render_template, url_for, request, current_app
from flask_login import login_required, current_user
from flask_restful import Resource, reqparse, abort, fields, marshal_with
from app import db, api, redis_cli, login_manager
from app.handlers.helper.oauth import OAuthSignIn
from app.handlers.helper.rate_limiter import Limiter
from app.models.user import User as UserModel
from app.utils.mail import send_email
from app.utils.captcha import generate_captcha

duplicate_pattern = re.compile("Duplicate entry '(?P<value>.+)' for key '(?P<filed>.+)'")

user_endpoint = Blueprint('user', __name__, url_prefix = '/users')


def __key_activate_email_code(email):
    return 'activate:email:{}'.format(email)


def _send_activate_email(email):
    key = __key_activate_email_code(email)
    activate_code = shortuuid.uuid()

    redis_cli.setex(key, timedelta(days = 1), activate_code)
    activate_url = url_for('user.activate_email',
                           e = base64.urlsafe_b64encode(email),
                           c = activate_code,
                           _external = True)
    send_email(email, u'邮箱激活', 'activate_email.html', activate_url = activate_url)


def __key_reset_password_code(email):
    return 'password:reset:email:{}'.format(email)


def _send_reset_password_email(email):
    key = __key_reset_password_code(email)
    reset_password_code = shortuuid.uuid()

    redis_cli.setex(key, timedelta(hours = 1), reset_password_code)
    reset_password_url = url_for('user.reset_password_page',
                                 e = base64.urlsafe_b64encode(email),
                                 c = reset_password_code,
                                 _external = True)
    send_email(email, u'重置密码', 'reset_password.html', reset_password_url = reset_password_url)


def _verify_reset_password_code(email, code):
    return code == redis_cli.getset(__key_reset_password_code(email), None)


def _get_user_by_email(email):
    user = UserModel.query.filter_by(email = email).first()
    if user is None:
        abort(404, message = 'user is not exists')

    return user


def __key_user_oauth_state(provider_name, user):
    return 'oauth:state:{}:{}'.format(provider_name, user.id)


def _set_user_oauth_state(provider_name):
    if current_user.is_authenticated:
        state = shortuuid.uuid()
        redis_cli.setex(__key_user_oauth_state(provider_name, current_user), timedelta(minutes = 1), state)
        return state
    return ''


def _get_user_oauth_state(provider_name):
    if current_user.is_authenticated:
        return redis_cli.get(__key_user_oauth_state(provider_name, current_user))
    return ''


def _login_user(user):
    session['api_token'] = user.login()


def __key_captcha(code):
    return 'captcha:img_code:{}'.format(code)


def _generate_captcha(email):
    b64_img, code = generate_captcha()
    redis_cli.setex(__key_captcha(code), current_app.config['LOGIN_CAPTCHA_EXPIRES_TIMEDELTA'], email)
    return b64_img


def _verify_captcha(email, code):
    val = redis_cli.getset(__key_captcha(code), None)
    return email == val


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

    activated = args['c'] == redis_cli.get(__key_activate_email_code(email))

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

        _send_activate_email(user.email)

        return {'id': user.id}, 201


@user_endpoint.route('/oauth/<provider_name>', methods = ['GET'])
def login_by_oauth(provider_name):
    provider = OAuthSignIn.get_provider(provider_name)
    if provider:
        return provider.authorize(state = _set_user_oauth_state(provider_name))
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
        if _get_user_oauth_state('github') != state:
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
        _login_user(user)

        return '登录成功'


@user_endpoint.route('/oauth/google/callback', methods = ['GET'])
def login_by_google_callback():
    """Github OAuth 回调
    """
    code, state, info = OAuthSignIn.get_provider('google').callback()
    if code is None:
        return 'google 授权失败'

    if current_user.is_authenticated:
        if _get_user_oauth_state('google') != state:
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
        _login_user(user)

        return '登录成功'


@api.resource('/users/email/active/resend')
class ResendActiveEmil(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', required = True)
        args = parser.parse_args()

        user = _get_user_by_email(args['email'])
        if user.activated:
            abort(403, message = 'user is already activated')

        _send_activate_email(user.email)
        return {}, 200


@api.resource('/captcha')
class Captcha(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', required = True)
        args = parser.parse_args()
        return {'captcha': _generate_captcha(args['email'])}, 200


@api.resource('/login')
class Login(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', required = True)
        parser.add_argument('password', required = True)
        parser.add_argument('code')
        args = parser.parse_args()

        ip_captcha_limiter = Limiter(
            redis_cli = redis_cli,
            keyfunc = lambda: 'login:limit:captcha:ip:{}'.format(request.remote_addr),
            limit = current_app.config['LOGIN_MAX_ATTEMPT_TIMES_PER_IP'],
            period = current_app.config['LOGIN_MAX_ATTEMPT_TIMEDELTA_PER_IP']
        )

        email_captcha_limiter = Limiter(
            redis_cli = redis_cli,
            keyfunc = lambda: 'login:limit:captcha:email:{}'.format(args['email']),
            limit = current_app.config['LOGIN_MAX_ATTEMPT_TIMES_PER_USER'],
            period = current_app.config['LOGIN_MAX_ATTEMPT_TIMEDELTA_PER_USER']
        )

        login_block_limiter = Limiter(
            redis_cli = redis_cli,
            keyfunc = lambda: 'login:limit:block:email:{}'.format(args['email']),
            limit = current_app.config['LOGIN_BLOCK_AFTER_MAX_ATTEMPT_TIMES'],
            period = current_app.config['LOGIN_BLOCK_TIMEDELTA_PER_USER']
        )

        should_carry_captcha = False
        if args['code']:
            should_carry_captcha = True
            if not _verify_captcha(args['email'], args['code']):
                abort(400, message = '验证码错误', captcha = _generate_captcha(args['email']))
        elif not ip_captcha_limiter.touch() or not email_captcha_limiter.touch():
            abort(429, captcha = _generate_captcha(args['email']))

        if not login_block_limiter.touch():
            abort(403, message = '尝试登录次数过多，请稍后尝试')

        user = UserModel.query.filter_by(email = args['email']).first()
        if user is None or not user.check_password(args['password']):
            payload = {'message': '用户名或密码错误'}
            if should_carry_captcha:
                payload['captcha'] = _generate_captcha(args['email'])
            abort(400, **payload)

        if not user.activated:
            abort(403, message = "用户未激活")

        _login_user(user)
        ip_captcha_limiter.reset()
        email_captcha_limiter.reset()
        login_block_limiter.reset()

        return {'message': '登录成功'}, 200


@api.resource('/logout')
class Logout(Resource):
    def post(self):
        if current_user.is_authenticated:
            current_user.logout()
        return {}, 200


@api.resource('/password')
class Password(Resource):
    @login_required
    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument('old_password', required = True)
        parser.add_argument('new_password', required = True)
        parser.add_argument('new_password2', required = True)
        args = parser.parse_args()

        if args['new_password'].strip() != args['new_password2'].strip():
            abort(400, message = '新密码输入不一致')

        if not current_user.check_password(args['old_password']):
            abort(403, message = '旧密码错误')

        current_user.set_password(args['new_password'].strip())
        db.session.commit()
        return {'message': '更新密码成功'}, 200

    def delete(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', required = True)
        args = parser.parse_args()

        user = UserModel.query.filter_by(email = args['email']).first()
        if user is None:
            abort(404, message = '请确认您是否是通过第三方账号登录的')

        _send_reset_password_email(args['email'])
        return {}, 200


@user_endpoint.route('/password/reset', methods = ['get'])
def reset_password_page():
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

    return render_template('reset_password.html', email = email, code = args['c'])


@api.resource('/password/reset', endpoint='reset_password')
class ResetPassword(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', required = True)
        parser.add_argument('new_password', required = True)
        parser.add_argument('new_password2', required = True)
        parser.add_argument('code', required = True)
        args = parser.parse_args()

        if not _verify_reset_password_code(args['email'], args['code']):
            abort(400, message = '页面已失效请重新申请重置密码')

        if args['new_password'].strip() != args['new_password2'].strip():
            abort(400, message = '新密码输入不一致')

        user = UserModel.query.filter_by(email = args['email']).first()
        if user is None:
            abort(404, message = '请确认您是否是通过第三方账号登录的')

        user.set_password(args['new_password'].strip())
        db.session.commit()
        return {'message': '重置成功'}, 200


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

    @marshal_with(user_fields)
    @login_required
    def patch(self):
        parser = reqparse.RequestParser()
        parser.add_argument('nickname')
        parser.add_argument('first_name')
        parser.add_argument('last_name')
        parser.add_argument('mobile')
        args = parser.parse_args()

        should_save = False
        for key, value in args.items():
            if hasattr(current_user, key):
                setattr(current_user, key, value)
                should_save = True

        if should_save:
            db.session.commit()

        return current_user


@login_manager.request_loader
def load_user_from_session(request):
    token = session.get('api_token')
    if token is not None:
        return UserModel.query.filter_by(api_token = token).first()
    return None
