# coding=utf-8
from rauth import OAuth2Service
from flask import current_app, url_for, request, redirect, json
from json import loads


class OAuthSignIn(object):
    providers = None

    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = current_app.config['OAUTH_CREDENTIALS'][provider_name]
        self.consumer_id = credentials['id']
        self.consumer_secret = credentials['secret']

    def authorize(self, state = ''):
        pass

    def callback(self):
        pass

    def get_callback_url(self):
        return url_for('user.login_by_%s_callback' % self.provider_name,
                       next = request.args.get('next') or request.referrer or None,
                       _external = True)

    @classmethod
    def get_provider(cls, provider_name):
        if cls.providers is None:
            cls.providers = {}
            for provider_class in cls.__subclasses__():
                provider = provider_class()
                cls.providers[provider.provider_name] = provider
        return cls.providers[provider_name]


class GithubSignIn(OAuthSignIn):
    def __init__(self):
        super(GithubSignIn, self).__init__('github')
        self.service = OAuth2Service(
            name = 'github',
            client_id = self.consumer_id,
            client_secret = self.consumer_secret,
            authorize_url = 'https://github.com/login/oauth/authorize',
            access_token_url = 'https://github.com/login/oauth/access_token',
            base_url = 'https://api.github.com/'
        )

    def authorize(self, state = ''):
        return redirect(self.service.get_authorize_url(redirect_uri = self.get_callback_url(), state = state))

    def callback(self):
        if 'code' not in request.args:
            return None, None, None

        code = request.args['code']
        state = request.args.get('state', '')
        oauth_session = self.service.get_auth_session(
            data = {
                'code': code,
                'redirect_uri': self.get_callback_url()
            }
        )
        userinfo = oauth_session.get('user').json()
        return code, state, userinfo


class GoogleSignIn(OAuthSignIn):
    def __init__(self):
        super(GoogleSignIn, self).__init__('google')
        self.service = OAuth2Service(
            name = 'google',
            client_id = self.consumer_id,
            client_secret = self.consumer_secret,
            authorize_url = 'https://accounts.google.com/o/oauth2/auth',
            access_token_url = 'https://accounts.google.com/o/oauth2/token',
            base_url = 'https://www.googleapis.com/oauth2/v1/'
        )

    def authorize(self, state = ''):
        return redirect(self.service.get_authorize_url(
            redirect_uri = self.get_callback_url(),
            state = state,
            response_type = 'code',
            scope = 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email'
        ))

    def callback(self):
        if 'code' not in request.args:
            return None, None, None

        code = request.args['code']
        state = request.args.get('state', '')
        oauth_session = self.service.get_auth_session(
            data = {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': self.get_callback_url()
            },
            decoder = loads
        )

        userinfo = oauth_session.get('userinfo').json()
        return code, state, userinfo
