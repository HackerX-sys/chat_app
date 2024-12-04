from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from src.core.models import User, Message
from src.core.extensions import db

ui = Blueprint('ui', __name__)

@ui.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('ui.chat'))
    return render_template('index.html')

@ui.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('ui.chat'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            user.online = True
            db.session.commit()
            return redirect(url_for('ui.chat'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@ui.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('ui.chat'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        else:
            user = User(
                username=username,
                password_hash=generate_password_hash(password)
            )
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('ui.chat'))
    
    return render_template('register.html')

@ui.route('/chat')
@login_required
def chat():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('chat.html', users=users)

@ui.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@ui.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    if 'bio' in request.form:
        current_user.bio = request.form['bio']
        db.session.commit()
        flash('Profile updated successfully', 'success')
    return redirect(url_for('ui.profile'))

@ui.route('/profile/settings', methods=['POST'])
@login_required
def update_settings():
    data = request.get_json()
    if 'notification_sound' in data:
        current_user.notification_sound = data['notification_sound']
    if 'desktop_notifications' in data:
        current_user.desktop_notifications = data['desktop_notifications']
    db.session.commit()
    return jsonify({'status': 'success'})

@ui.route('/logout')
@login_required
def logout():
    current_user.online = False
    db.session.commit()
    logout_user()
    return redirect(url_for('ui.index'))
