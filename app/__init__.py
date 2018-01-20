# coding=utf8
import traceback
import re
from flask import Flask, json, current_app, request, abort
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy, get_debug_queries
from flask_session import Session
from flask_restful import Api
from sqlalchemy.exc import SQLAlchemyError
from flask_mail import Mail
import redis

from config import config, Config

duplicate_pattern = re.compile("Duplicate entry '(?P<value>.+)' for key '(?P<filed>.+)'")

db = SQLAlchemy()
mail = Mail()
session = Session()
api = Api()
redis_cli = redis.StrictRedis()

login_manager = LoginManager()
login_manager.session_protection = 'strong'


def init_redis_cli(config):
    global redis_cli
    if config['REDIS_HOST']:
        redis_cli = redis.StrictRedis(host = config['REDIS_HOST'])


def create_app(config_name):
    app = Flask(__name__)

    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    init_redis_cli(app.config)
    app.config['SESSION_REDIS'] = redis_cli

    db.init_app(app)
    mail.init_app(app)
    session.init_app(app)

    login_manager.init_app(app)
    login_manager.unauthorized_handler(lambda: abort(401))

    # additional log after request
    def make_additional_log():
        def log_slow_query(response):
            """慢查询记录
            """
            for query in get_debug_queries():
                if query.duration >= current_app.config['SLOW_DB_QUERY_TIME']:
                    current_app.logger.warning(
                        'Slow query: %s\nParameters: %s\nDuration: %fs\nContext: %s\n'
                        % (query.statement, query.parameters, query.duration,
                           query.context))
            return response

        app.after_request(log_slow_query)

    make_additional_log()

    # app level error handler
    def make_error_handler():
        def log_exception(e):
            current_app.logger.warning(e)
            traceback.print_exc()

            if isinstance(e, SQLAlchemyError):
                match = duplicate_pattern.search(e.args[0])
                if match:
                    groups = {
                        'value': match.group('value'),
                        'filed': match.group('filed')
                    }
                    abort(409, ({'message': "duplicate value '{value}' for key '{filed}'".format(**groups), **groups}))
                db.session.rollback()

            abort(500)

        # error handler
        app.register_error_handler(Exception, log_exception)

    make_error_handler()

    from app.handlers.user import user_endpoint
    app.register_blueprint(user_endpoint)

    api.init_app(app)

    return app
