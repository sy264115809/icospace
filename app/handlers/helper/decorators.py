from functools import wraps
from flask_restful import abort
from flask_login import current_user


def admin_required(func):
    @wraps(func)
    def decorator(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        elif not current_user.is_admin:
            abort(401)
        else:
            return func(*args, **kwargs)

    return decorator
