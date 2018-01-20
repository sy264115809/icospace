from app import db
from app.models import IntEnum
from datetime import datetime
from enum import Enum


class Tournament(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(64), unique = True)
    description = db.Column(db.Text)
    detail = db.Column(db.Text)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default = datetime.now)
    updated_at = db.Column(db.DateTime, default = datetime.now, onupdate = datetime.now)

    @property
    def is_ongoing(self):
        now = datetime.now()
        return self.start_time <= now < self.end_time


class SubmissionStatus(Enum):
    new = 0
    pending = 1
    finished = 2


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    upload_filename = db.Column(db.String(128))
    upload_file_content = db.Column(db.LargeBinary)
    task_id = db.Column(db.String(128))
    status = db.Column(IntEnum(SubmissionStatus), default = SubmissionStatus.new)
    result = db.Column(db.JSON)  # 如果mysql 版本过低或希望能在模型上更分离一些可以另外拆一个模型
    score = db.Column(db.Float, default = 0)

    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    owner = db.relationship('User', backref = db.backref('submissions'))
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'))
    tournament = db.relationship('Tournament', backref = db.backref('submissions'))

    uploaded_at = db.Column(db.DateTime, default = datetime.now)  # created_at
    finished_at = db.Column(db.DateTime)

    def attach_task(self, task_id):
        self.task_id = task_id
        self.status = SubmissionStatus.pending
