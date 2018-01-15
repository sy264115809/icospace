# coding=utf-8
import os

if os.path.exists('.env'):
    print('Importing environment from .env...')
    for line in open('.env'):
        if line.startswith('#'):
            continue
        var = line.strip().split('=', 1)
        if len(var) == 2:
            os.environ[var[0]] = var[1]

from app import create_app, db
from flask import url_for
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand

app = create_app(os.getenv('ICO_CONFIG') or 'default')

migrate = Migrate(app, db)
manager = Manager(app)


def make_shell_context():
    return dict(app = app, db = db)

@manager.command
def list_routes():
    import urllib
    output = []
    for rule in app.url_map.iter_rules():

        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)

        methods = ','.join(rule.methods)
        url = url_for(rule.endpoint, **options)
        line = urllib.unquote("{:50s} {:20s} {}".format(rule.endpoint, methods, url))
        output.append(line)

    for line in sorted(output):
        print line


manager.add_command("shell", Shell(make_context = make_shell_context))
manager.add_command('db', MigrateCommand)

if __name__ == '__main__':
    manager.run()
