from app import redis_cli, db
from app.models.tournament import Submission, SubmissionStatus
from pickle import dumps, loads
from random import randint
from datetime import datetime
from uuid import uuid1


# from json import dumps, loads


class SubmissionTask:
    def __init__(self, submission_id, data):
        self.id = uuid1()
        self.submission_id = submission_id
        self.data = data

    def do(self):
        submission = Submission.query.filter_by(id = self.submission_id).first()
        if submission is None or submission.status == SubmissionStatus.finished:
            return

        submission.result = {'result': 'good'}
        submission.score = randint(1, 100)
        submission.finished_at = datetime.now()
        submission.status = SubmissionStatus.finished
        db.session.commit()
        return submission


__key_submission_task_queue = 'task:submission:queue'


def __key_submission_task(task_id):
    return 'task:submission:{}'.format(task_id)


def push_submission_task(task):
    if not isinstance(task, SubmissionTask):
        raise TypeError
    pipe = redis_cli.pipeline()
    pipe.rpush(__key_submission_task_queue, task.id)
    pipe.set(__key_submission_task(task.id), dumps(task))
    pipe.execute()
    return task.id


def pop_submission_task():
    task_id = redis_cli.lpop(__key_submission_task_queue)
    if task_id is not None:
        key = __key_submission_task(task_id.decode('utf8'))
        task = loads(redis_cli.get(key))
        redis_cli.delete(key)
        return task
