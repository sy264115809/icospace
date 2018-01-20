from flask import current_app
from flask_restful import Resource, reqparse, abort, fields, marshal_with
from flask_login import login_required, current_user
from werkzeug.datastructures import FileStorage
from app import api, db
from app.handlers.user import user_fields
from app.handlers.helper.decorators import admin_required
from app.models.tournament import Tournament as TournamentModel, Submission as SubmissionModel, SubmissionStatus
from app.tasks.submission import SubmissionTask, push_submission_task, pop_submission_task
from datetime import datetime
from os.path import splitext


def _input_type_datetime(val):
    return datetime.strptime(val, '%Y-%m-%dT%H:%M:%S')


tournament_fields = {
    'id': fields.Integer,
    'name': fields.String(default = ''),
    'description': fields.String(default = ''),
    'detail': fields.String(default = ''),
    'start_time': fields.DateTime(dt_format = 'iso8601'),
    'end_time': fields.DateTime(dt_format = 'iso8601'),
    'created_at': fields.DateTime(dt_format = 'iso8601'),
    'updated_at': fields.DateTime(dt_format = 'iso8601')
}

tournament_list_fields = {
    'items': fields.List(fields.Nested(tournament_fields))
}


@api.resource('/tournaments', endpoint = 'tournament_list')
class TournamentList(Resource):
    @login_required
    @admin_required
    @marshal_with(tournament_fields)
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', required = True)
        parser.add_argument('description', required = True)
        parser.add_argument('detail', required = True)
        parser.add_argument('start_time', type = _input_type_datetime, required = True)
        parser.add_argument('end_time', type = _input_type_datetime, required = True)
        args = parser.parse_args()

        if not args['start_time'] < args['end_time']:
            abort(400, message = '"end_time" should be greater than "start_time"')

        tournament = TournamentModel(
            name = args['name'],
            description = args['description'],
            detail = args['detail'],
            start_time = args['start_time'],
            end_time = args['end_time']
        )

        db.session.add(tournament)
        db.session.commit()

        return tournament

    @login_required
    @marshal_with(tournament_list_fields)
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name')
        parser.add_argument('start_time_gt', type = _input_type_datetime)
        parser.add_argument('start_time_lt', type = _input_type_datetime)
        parser.add_argument('end_time_gt', type = _input_type_datetime)
        parser.add_argument('end_time_lt', type = _input_type_datetime)
        args = parser.parse_args()

        query = TournamentModel.query
        if args['name']:
            query = query.filter(TournamentModel.name.contains(args['name']))
        if args['start_time_gt']:
            query = query.filter(TournamentModel.start_time > args['start_time_gt'])
        if args['start_time_lt']:
            query = query.filter(TournamentModel.start_time < args['start_time_lt'])
        if args['end_time_gt']:
            query = query.filter(TournamentModel.end_time > args['end_time_gt'])
        if args['end_time_lt']:
            query = query.filter(TournamentModel.end_time < args['end_time_lt'])

        tournaments = query.all()
        return {'items': tournaments}


def _get_tournament_by_id(id):
    tournament = TournamentModel.query.filter_by(id = id).first()
    if tournament is None:
        abort(404)

    return tournament


@api.resource('/tournaments/<id>')
class Tournament(Resource):
    @login_required
    @marshal_with(tournament_fields)
    def get(self, id):
        tournament = _get_tournament_by_id(id)
        return tournament

    @login_required
    @admin_required
    @marshal_with(tournament_fields)
    def patch(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name')
        parser.add_argument('description')
        parser.add_argument('detail')
        parser.add_argument('start_time', type = _input_type_datetime)
        parser.add_argument('end_time', type = _input_type_datetime)
        args = parser.parse_args()

        tournament = _get_tournament_by_id(id)

        should_save = False
        for key, value in args.items():
            if hasattr(tournament, key):
                setattr(tournament, key, value)
                should_save = True

        if should_save:
            db.session.commit()

        return tournament

    @login_required
    @admin_required
    def delete(self):
        tournament = _get_tournament_by_id(id)
        db.session.delete(tournament)
        db.session.commit()
        return {}, 200


def _submission_file_parser(ext):
    def csv_parser(data):
        # TODO
        return data

    try:
        return {
            '.csv': csv_parser
        }[ext]
    except KeyError:
        return None


def _input_type_submission_status(val):
    if int(val) not in [v.value for v in list(SubmissionStatus.__members__.values())]:
        raise TypeError
    return SubmissionStatus(int(val))


class SubmissionStatusField(fields.Raw):
    def __init__(self, **kwargs):
        super(SubmissionStatusField, self).__init__(**kwargs)

    def format(self, status):
        return status.value

    def output(self, key, obj):
        if hasattr(obj, 'status'):
            return self.format(obj.status)
        return 0


submission_fields = {
    'id': fields.Integer,
    'upload_filename': fields.String(default = ''),
    'upload_file_content': fields.String(default = ''),
    'task_id': fields.String(default = ''),
    'status': SubmissionStatusField,
    'result': fields.Raw,
    'score': fields.Float,
    'owner': fields.Nested(user_fields),
    'tournament': fields.Nested(tournament_fields),
    'uploaded_at': fields.DateTime(dt_format = 'iso8601'),
    'finished_at': fields.DateTime(dt_format = 'iso8601')
}

submission_list_fields = {
    'items': fields.List(fields.Nested(submission_fields))
}


@api.resource('/tournaments/<tid>/submissions')
class SubmissionOfTournament(Resource):
    @login_required
    @marshal_with(submission_fields)
    def post(self, tid):
        parser = reqparse.RequestParser()
        parser.add_argument('attachment', type = FileStorage, location = 'files', required = True)
        args = parser.parse_args()

        file = args['attachment']
        filename, ext = splitext(file.filename)
        file_parser = _submission_file_parser(ext)
        if file_parser is None:
            abort(400, message = '不支持的文件类型: {}'.format(ext))

        data = file.read()

        submission = SubmissionModel(
            upload_filename = file.filename,
            upload_file_content = data,
            owner_id = current_user.id,
            tournament_id = tid
        )
        db.session.add(submission)
        db.session.commit()

        try:
            task = SubmissionTask(
                submission_id = submission.id,
                data = file_parser(data)
            )
            task_id = push_submission_task(task)
            submission.attach_task(task_id)
            db.session.commit()
        except Exception as e:
            # 如果任务推入队列失败，不会影响 submission 的创建
            # 需要依赖其他 Daemon 定时扫描 status = new 的 submission
            # 并重复尝试为其生成 task
            current_app.logger.error('create task failed:{}'.format(e))
            pass

        return submission, 200

    @login_required
    @marshal_with(submission_list_fields)
    def get(self, tid):
        parser = reqparse.RequestParser()
        parser.add_argument('owner_id', type = int)
        parser.add_argument('status', type = _input_type_submission_status)
        args = parser.parse_args()

        query = SubmissionModel.query.filter_by(tournament_id = tid)
        if not current_user.is_admin:
            query = query.filter_by(owner_id = current_user.id)
        elif args['owner_id']:
            query = query.filter_by(owner_id = args['owner_id'])

        if args['status']:
            query = query.filter_by(status = args['status'])

        submissions = query.all()
        return {'items': submissions}


@api.resource('/submissions/task')
class DoSubmissionTask(Resource):
    """手动触发从任务队列中获取一个任务并执行，仅用于演示
    """

    @login_required
    @admin_required
    @marshal_with(submission_fields)
    def post(self):
        task = pop_submission_task()
        if task is not None:
            submission = task.do()
            return submission
