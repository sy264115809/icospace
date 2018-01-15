from threading import Thread
from flask import current_app, render_template
from flask_mail import Message
from app import mail


def _send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(to, subject, template, **kwargs):
    app = current_app._get_current_object()
    msg = Message(subject = subject, recipients = [to])
    msg.html = render_template('mails/' + template, **kwargs)
    thr = Thread(target = _send_async_email, args = [app, msg])
    thr.start()
    return thr
