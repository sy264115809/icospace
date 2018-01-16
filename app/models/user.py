from datetime import datetime
from itsdangerous import JSONWebSignatureSerializer as Serializer
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app
from flask_login import UserMixin
from app import db


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    first_name = db.Column(db.String(32))
    last_name = db.Column(db.String(32))
    nickname = db.Column(db.String(32))
    email = db.Column(db.String(64), unique = True, default = None)
    mobile = db.Column(db.String(16), unique = True, default = None)
    password_hash = db.Column(db.String(512))

    # github oauth
    github_id = db.Column(db.String(32), unique = True)
    github_login = db.Column(db.String(64))
    github_name = db.Column(db.String(32))
    github_email = db.Column(db.String(64))

    google_id = db.Column(db.String(32), unique = True)
    google_name = db.Column(db.String(32))
    google_email = db.Column(db.String(64))

    api_token = db.Column(db.String(512))

    login_count = db.Column(db.Integer, default = 0)
    last_login_at = db.Column(db.DateTime)

    activated = db.Column(db.Boolean, default = False)
    disabled = db.Column(db.Boolean, default = False)

    created_at = db.Column(db.DateTime, default = datetime.now)
    updated_at = db.Column(db.DateTime, default = datetime.now, onupdate = datetime.now)

    def __init__(self, password = '', **kwargs):
        self.login_count = 0
        if password:
            self.set_password(password)
        super(User, self).__init__(**kwargs)

    def __repr__(self):
        return '<User %r>' % self.id

    def is_active(self):
        return self.activated and not self.disabled

    def generate_api_token(self):
        s = Serializer(current_app.config['SECRET_KEY'], salt = datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        self.api_token = s.dumps({'id': self.id})

    def login(self):
        self.login_count += 1
        self.last_login_at = datetime.now()
        self.generate_api_token()
        db.session.commit()
        return self.api_token

    def logout(self):
        self.api_token = ''
        db.session.commit()

    def set_password(self, pwd):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)
