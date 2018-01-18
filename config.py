import os
from datetime import timedelta


class Config(object):
    SERVER_NAME = 'localhost:5000'
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SLOW_DB_QUERY_TIME = 0.5

    SESSION_COOKIE_NAME = 'SESSION_ID'
    PERMANENT_SESSION_LIFETIME = timedelta(days = 7)
    SESSION_TYPE = 'redis'
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'ico:session:'

    REDIS_HOST = os.environ.get('REDIS_HOST') or '127.0.0.1'

    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_RECORD_QUERIES = True
    # SQLALCHEMY_ECHO = True

    LOGIN_MAX_ATTEMPT_TIMES_PER_USER = 5  # when user try to login touch the max times, should provide captcha
    LOGIN_MAX_ATTEMPT_TIMEDELTA_PER_USER = timedelta(minutes = 5)
    LOGIN_MAX_ATTEMPT_TIMES_PER_IP = 10  # when user try to login touch the max times, should provide captcha
    LOGIN_MAX_ATTEMPT_TIMEDELTA_PER_IP = timedelta(minutes = 5)
    LOGIN_BLOCK_AFTER_MAX_ATTEMPT_TIMES = 10  # after user trying to login touch the max times should be block
    LOGIN_BLOCK_TIMEDELTA_PER_USER = timedelta(minutes = 10)
    LOGIN_CAPTCHA_EXPIRES_TIMEDELTA = timedelta(minutes = 1)

    MAIL_SERVER = 'smtp.qq.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_DEBUG = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = 'Notification <shaoyu@qq.com>'

    APPLICATION_ERROR_NOTIFICATION_FROM_ADDR = 'Notification <shaoyu@qq.com>'
    APPLICATION_ERROR_NOTIFICATION_SUBJECT = '[ICO Platform] Application Error'
    APPLICATION_ERROR_NOTIFICATION_TO_ADDRS = [
        "shaoyu@qq.com"
    ]

    REDIS_URL = 'redis://localhost:6379'

    OAUTH_CREDENTIALS = {
        'github': {
            'id': os.environ.get('OAUTH_GITHUB_ID'),
            'secret': os.environ.get('OAUTH_GITHUB_SECRET')
        },
        'google': {
            'id': os.environ.get('OAUTH_GOOGLE_ID'),
            'secret': os.environ.get('OAUTH_GOOGLE_SECRET')
        }
    }

    @classmethod
    def init_app(cls, app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SECRET_KEY = 'secretkey'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
                              'mysql://root:root@127.0.0.1:3306/ico?charset=utf8'


class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = 'secretkey'
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
                              'mysql://root:root@127.0.0.1:3306/ico_test?charset=utf8'
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'mysql://root:root@127.0.0.1:3306/ico?charset=utf8'

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)

        # email errors to the administrators
        import logging
        from logging.handlers import SMTPHandler
        credentials = None
        secure = None
        if getattr(cls, 'MAIL_USERNAME', None) is not None:
            credentials = (cls.MAIL_USERNAME, cls.MAIL_PASSWORD)
            if getattr(cls, 'MAIL_USE_TLS', None):
                secure = ()
        mail_handler = SMTPHandler(
            mailhost = (cls.MAIL_SERVER, cls.MAIL_PORT),
            fromaddr = cls.APPLICATION_ERROR_NOTIFICATION_FROM_ADDR,
            toaddrs = [cls.APPLICATION_ERROR_NOTIFICATION_TO_ADDRS],
            subject = cls.APPLICATION_ERROR_NOTIFICATION_SUBJECT,
            credentials = credentials,
            secure = secure)
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)


class GunicornConfig(ProductionConfig):
    @classmethod
    def init_app(cls, app):
        ProductionConfig.init_app(app)

        # add handler to redirect to gunicorn error
        import logging
        app.logger.setLevel(logging.DEBUG)
        app.logger.handlers.extend(logging.getLogger("gunicorn.error").handlers)


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'gunicorn': GunicornConfig,

    'default': DevelopmentConfig
}
