from functools import wraps
import hmac
import bcrypt
from flask import redirect, url_for, flash
from flask_login import LoginManager, current_user
from models import User

login_manager = LoginManager()
login_manager.login_view = 'web.login'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def authenticate_dyndns_user(username, password):
    if not username or not password:
        return None
    user = User.query.filter_by(username=username).first()
    if not user or not user.is_active:
        return None
    valid_user = hmac.compare_digest(user.username, username)
    try:
        valid_pass = bcrypt.checkpw(password.encode('utf8'), user.password_hash.encode())
    except (ValueError, TypeError):
        return None
    if valid_user and valid_pass:
        return user
    return None


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('web.login'))
        return f(*args, **kwargs)
    return decorated_function
