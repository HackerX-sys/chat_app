from flask import Blueprint, render_template, request, jsonify, abort
from flask_login import login_required, current_user
from functools import wraps
from ..core.models import db, User, Message

admin = Blueprint('admin', __name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@admin.route('/dashboard')
@login_required
@admin_required
def dashboard():
    total_users = User.query.count()
    total_messages = Message.query.count()
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_messages = Message.query.order_by(Message.timestamp.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_messages=total_messages,
                         recent_users=recent_users,
                         recent_messages=recent_messages)

@admin.route('/users')
@login_required
@admin_required
def users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@admin.route('/messages')
@login_required
@admin_required
def messages():
    messages = Message.query.order_by(Message.timestamp.desc()).all()
    return render_template('admin/messages.html', messages=messages)
