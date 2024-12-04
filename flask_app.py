import os
import random
import string
import json
import logging
import sys
import ssl
from datetime import datetime, timedelta
from functools import wraps
import uuid

# Monkey patch for gevent
from gevent import monkey
monkey.patch_all()

# Advanced Imports
import emoji
import redis
import numpy as np
import pandas as pd
import torch
import langdetect
from googletrans import Translator
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote, urljoin
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Local Imports
from config import get_config

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(get_config())

# Template filters
@app.template_filter('format_time')
def format_time(timestamp):
    if not timestamp:
        return ""
    return timestamp.strftime("%I:%M %p")

@app.template_filter('timeago')
def timeago(timestamp):
    """Convert a timestamp to a human readable relative time string"""
    if not timestamp:
        return ""
    
    now = datetime.utcnow()
    diff = now - timestamp
    
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return "just now"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} {'minute' if minutes == 1 else 'minutes'} ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} {'hour' if hours == 1 else 'hours'} ago"
    elif seconds < 604800:
        days = int(seconds / 86400)
        return f"{days} {'day' if days == 1 else 'days'} ago"
    elif seconds < 2592000:
        weeks = int(seconds / 604800)
        return f"{weeks} {'week' if weeks == 1 else 'weeks'} ago"
    elif seconds < 31536000:
        months = int(seconds / 2592000)
        return f"{months} {'month' if months == 1 else 'months'} ago"
    else:
        years = int(seconds / 31536000)
        return f"{years} {'year' if years == 1 else 'years'} ago"

@app.template_filter('avatar')
def avatar_filter(user):
    """Generate avatar data for a user"""
    if not user:
        return {
            'color': '#E1E1E1',
            'initials': '?'
        }
    
    # Generate a consistent color based on username
    username = user.username if hasattr(user, 'username') else str(user)
    hash_value = sum(ord(c) for c in username)
    hue = hash_value % 360
    color = f'hsl({hue}, 70%, 80%)'
    
    # Get initials from username
    initials = ''.join(word[0].upper() for word in username.split()[:2])
    if not initials:
        initials = username[0].upper()
    
    return {
        'color': color,
        'initials': initials[:2]
    }

@app.template_filter('default_avatar')
def default_avatar_filter(user):
    """Template filter to get user's avatar info."""
    if user.avatar_url:
        return {'url': user.avatar_url}
    return avatar_filter(user.username)

# Session configuration for multiple accounts
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)
app.config['SESSION_FILE_DIR'] = os.path.join(app.root_path, 'flask_session')

# Create session directory if it doesn't exist
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

# Initialize database
db = SQLAlchemy(app)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["1000 per day", "100 per hour"]
)

# Initialize SocketIO with config
socketio_config = {
    'logger': True,
    'engineio_logger': True,
    'cors_allowed_origins': '*',
    'ping_timeout': 60,
    'ping_interval': 25,
}
socketio = SocketIO(app, **socketio_config)

def import_transformers():
    """Lazy import of transformers to avoid startup issues"""
    global transformers
    if not hasattr(import_transformers, 'transformers'):
        try:
            import transformers
        except ImportError:
            logger.error("Failed to import transformers module")
            return None
    return transformers

# Model definitions
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    message_type = db.Column(db.String(20), default='text')
    chat_type = db.Column(db.String(20), default='private')  # 'private' or 'group'
    read = db.Column(db.Boolean, default=False)
    edited = db.Column(db.Boolean, default=False)
    edited_timestamp = db.Column(db.DateTime, nullable=True)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    file_url = db.Column(db.String(200), nullable=True)
    file_type = db.Column(db.String(50), nullable=True)
    file_name = db.Column(db.String(100), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)
    is_pinned = db.Column(db.Boolean, default=False)
    language = db.Column(db.String(10), nullable=True)
    sentiment = db.Column(db.Float, nullable=True)
    
    replies = db.relationship('Message', 
        backref=db.backref('parent', remote_side=[id]),
        foreign_keys=[reply_to_id],
        lazy='dynamic'
    )

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    public_id = db.Column(db.String(8), unique=True)
    is_admin = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='offline')
    theme = db.Column(db.String(20), default='light')
    bio = db.Column(db.String(500))
    notification_sound = db.Column(db.Boolean, default=True)
    desktop_notifications = db.Column(db.Boolean, default=True)
    message_preview = db.Column(db.Boolean, default=True)
    read_receipts = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    avatar_url = db.Column(db.String(200), nullable=True)
    
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy=True)
    groups = db.relationship('Group', secondary='group_members', backref=db.backref('members', lazy=True))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def get_friends(self):
        sent_friends = Friend.query.filter_by(user_id=self.id, status='accepted').all()
        received_friends = Friend.query.filter_by(friend_id=self.id, status='accepted').all()
        friends = []
        for friend in sent_friends:
            friends.append(friend.friend)
        for friend in received_friends:
            friends.append(friend.user)
        return friends

    def is_friend_with(self, user):
        return Friend.query.filter(
            ((Friend.user_id == self.id) & (Friend.friend_id == user.id) |
             (Friend.user_id == user.id) & (Friend.friend_id == self.id)) &
            (Friend.status == 'accepted')
        ).first() is not None

    def has_sent_friend_request_to(self, user):
        return Friend.query.filter_by(
            user_id=self.id,
            friend_id=user.id,
            status='pending'
        ).first() is not None

    def has_received_friend_request_from(self, user):
        return Friend.query.filter_by(
            user_id=user.id,
            friend_id=self.id,
            status='pending'
        ).first() is not None

    def get_friend_requests(self):
        return Friend.query.filter_by(friend_id=self.id, status='pending').all()

    def get_sent_requests(self):
        return Friend.query.filter_by(user_id=self.id, status='pending').all()

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    avatar = db.Column(db.String(200))
    is_private = db.Column(db.Boolean, default=False)
    messages = db.relationship('Message', backref='group', lazy=True)
    pinned_messages = db.relationship('Message',
        primaryjoin="and_(Message.group_id==Group.id, Message.is_pinned==True)",
        lazy=True,
        overlaps="messages,group"
    )

class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('friends_sent', lazy='dynamic'))
    friend = db.relationship('User', foreign_keys=[friend_id], backref=db.backref('friends_received', lazy='dynamic'))
    
    __table_args__ = (db.UniqueConstraint('user_id', 'friend_id', name='unique_friendship'),)

class GroupMember(db.Model):
    __tablename__ = 'group_members'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    muted_until = db.Column(db.DateTime, nullable=True)

class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    query = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('search_history', lazy=True))

class CallLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    caller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    call_type = db.Column(db.String(10), nullable=False)
    duration = db.Column(db.Integer)
    caller = db.relationship('User', foreign_keys=[caller_id], backref='calls_made')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='calls_received')

class FriendRequest(db.Model):
    __tablename__ = 'friend_requests'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_requests', lazy='dynamic'))
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref=db.backref('received_requests', lazy='dynamic'))
    
    __table_args__ = (
        db.UniqueConstraint('sender_id', 'receiver_id', name='unique_request'),
    )

# Create tables
def init_db():
    with app.app_context():
        # Drop all tables first to ensure clean state
        db.drop_all()
        # Create all tables
        db.create_all()
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                is_admin=True,
                status='offline',
                theme='light',
                public_id=str(uuid.uuid4())[:8]
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    if not user_id:
        return None
    return User.query.get(int(user_id))

def get_current_sessions():
    """Get all active sessions for the current browser"""
    return session.get('active_sessions', [])

def add_session(user_id):
    """Add a new session for a user"""
    sessions = get_current_sessions()
    if user_id not in sessions:
        sessions.append(user_id)
        session['active_sessions'] = sessions

def remove_session(user_id):
    """Remove a session for a user"""
    sessions = get_current_sessions()
    if user_id in sessions:
        sessions.remove(user_id)
        session['active_sessions'] = sessions

# Translation and AI Services
translator = Translator()

def get_nlp_model():
    """Lazy loading of the NLP model"""
    global nlp_model
    if not hasattr(get_nlp_model, 'nlp_model'):
        try:
            transformers = import_transformers()
            if transformers is None:
                return None
            get_nlp_model.nlp_model = transformers.pipeline('text-classification')
        except Exception as e:
            logger.error(f"Failed to load NLP model: {str(e)}")
            get_nlp_model.nlp_model = None
    return get_nlp_model.nlp_model

# AI-Powered Message Suggestion Function
def get_message_suggestions(message_content):
    try:
        model = get_nlp_model()
        if model is None:
            return []
            
        # Get sentiment
        sentiment = model(message_content)[0]
        
        # Basic suggestions based on sentiment
        suggestions = []
        if sentiment['label'] == 'POSITIVE':
            suggestions.extend([
                "That's great to hear!",
                "I'm glad things are going well!",
                "Awesome news!"
            ])
        elif sentiment['label'] == 'NEGATIVE':
            suggestions.extend([
                "I'm sorry to hear that.",
                "That must be difficult.",
                "Let me know if you need any help."
            ])
        
        return suggestions[:3]  # Return top 3 suggestions
    except Exception as e:
        logger.error(f"Error generating message suggestions: {str(e)}")
        return []

# SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('message')
def handle_message(data):
    print('Received message:', data)
    chat_id = data.get('chat_id')
    chat_type = data.get('chat_type')
    message_type = data.get('type', 'text')
    
    if chat_id and chat_type:
        room = f"{chat_type}_{chat_id}"
        emit('message', data, room=room)
        
        # Save message to database
        try:
            message = Message(
                sender_id=current_user.id,
                content=data.get('content') or data.get('message'),
                message_type=message_type,
                chat_type=chat_type
            )
            
            if chat_type == 'private':
                message.recipient_id = chat_id
            else:
                message.group_id = chat_id
                
            db.session.add(message)
            db.session.commit()
        except Exception as e:
            print('Error saving message:', str(e))

@socketio.on('typing')
def handle_typing(data):
    user_id = data.get('user_id')
    target_id = data.get('target_id')
    status = data.get('status')
    
    if user_id and target_id:
        emit('typing_update', {
            'user_id': user_id,
            'status': status
        }, room=f"private_{target_id}")

@socketio.on('join')
def on_join(data):
    room = f"{data.get('chat_type')}_{data.get('chat_id')}"
    join_room(room)
    print(f"User joined room: {room}")

@socketio.on('leave')
def on_leave(data):
    room = f"{data.get('chat_type')}_{data.get('chat_id')}"
    leave_room(room)
    print(f"User left room: {room}")

# Call handling
@socketio.on('call_request')
def handle_call_request(data):
    target_id = data.get('target_id')
    call_type = data.get('call_type')
    if target_id:
        emit('incoming_call', {
            'caller_id': current_user.id,
            'call_type': call_type
        }, room=f"private_{target_id}")

@socketio.on('call_response')
def handle_call_response(data):
    caller_id = data.get('caller_id')
    response = data.get('response')
    if caller_id:
        emit('call_' + response, {
            'responder_id': current_user.id
        }, room=f"private_{caller_id}")

@socketio.on('ice_candidate')
def handle_ice_candidate(data):
    target_id = data.get('target_id')
    if target_id:
        emit('ice_candidate', {
            'candidate': data.get('candidate'),
            'sender_id': current_user.id
        }, room=f"private_{target_id}")

@socketio.on('offer')
def handle_offer(data):
    target_id = data.get('target_id')
    if target_id:
        emit('offer', {
            'offer': data.get('offer'),
            'sender_id': current_user.id
        }, room=f"private_{target_id}")

@socketio.on('answer')
def handle_answer(data):
    target_id = data.get('target_id')
    if target_id:
        emit('answer', {
            'answer': data.get('answer'),
            'sender_id': current_user.id
        }, room=f"private_{target_id}")

# WebRTC imports and configuration
import json
import logging
import warnings
import platform

# Configure logging
logging.basicConfig(level=logging.WARNING)
warnings.filterwarnings('ignore', message='.*Xformers is not installed correctly.*')

# Store active peer connections and calls
active_calls = {}  # Format: {call_id: {'caller_id': id, 'receiver_id': id, 'start_time': datetime, 'type': 'voice/video'}}

# WebRTC signaling handlers
@socketio.on('webrtc_offer')
def handle_webrtc_offer(data):
    target_id = data.get('target')
    if target_id:
        socketio.emit('webrtc_offer', data, room=target_id)

@socketio.on('webrtc_answer')
def handle_webrtc_answer(data):
    target_id = data.get('target')
    if target_id:
        socketio.emit('webrtc_answer', data, room=target_id)

@socketio.on('webrtc_ice_candidate')
def handle_ice_candidate(data):
    target_id = data.get('target')
    if target_id:
        socketio.emit('webrtc_ice_candidate', data, room=target_id)

@socketio.on('call_request')
def handle_call_request(data):
    target_id = data.get('target_id')
    call_type = data.get('call_type')  # 'video' or 'voice'
    
    # Emit call request to target user
    socketio.emit('incoming_call', {
        'caller_id': current_user.id,
        'caller_name': current_user.username,
        'call_type': call_type
    }, room=str(target_id))

@socketio.on('call_response')
def handle_call_response(data):
    caller_id = data.get('caller_id')
    accepted = data.get('accepted')
    
    if accepted:
        # Create a new peer connection for this call
        # pc = RTCPeerConnection()
        # peer_connections[f"{current_user.id}-{caller_id}"] = pc
        
        # Emit acceptance to caller
        socketio.emit('call_accepted', {
            'target_id': current_user.id,
            'target_name': current_user.username
        }, room=str(caller_id))
    else:
        # Emit rejection to caller
        socketio.emit('call_rejected', {
            'target_id': current_user.id,
            'target_name': current_user.username
        }, room=str(caller_id))

@socketio.on('end_call')
def handle_end_call(data):
    caller_id = current_user.id
    target_id = data.get('target_id')
    call_id = f"{caller_id}-{target_id}"
    reverse_call_id = f"{target_id}-{caller_id}"
    
    # Find the correct call ID
    actual_call_id = call_id if call_id in active_calls else reverse_call_id
    
    if actual_call_id in active_calls:
        call_data = active_calls[actual_call_id]
        
        # Update call log
        call_log = CallLog.query.get(call_data['log_id'])
        if call_log:
            call_log.end_time = datetime.utcnow()
            call_log.duration = int((datetime.utcnow() - call_log.start_time).total_seconds())
            db.session.commit()
        
        # Notify admins of call end
        admin_users = User.query.filter_by(is_admin=True).all()
        for admin in admin_users:
            socketio.emit('call_ended_admin', {
                'call_id': actual_call_id
            }, room=str(admin.id))
        
        # Remove from active calls
        del active_calls[actual_call_id]
    
    # Notify the target user
    socketio.emit('call_ended', {
        'user_id': current_user.id,
        'username': current_user.username
    }, room=str(target_id))

@socketio.on('call_accepted')
def handle_call_accepted(data):
    caller_id = data.get('caller_id')
    target_id = data.get('target_id')
    call_type = data.get('call_type')
    
    # Create call log entry
    call_log = CallLog(
        caller_id=caller_id,
        receiver_id=target_id,
        call_type=call_type
    )
    db.session.add(call_log)
    db.session.flush()
    
    # Track active call
    call_id = f"{caller_id}-{target_id}"
    active_calls[call_id] = {
        'caller_id': caller_id,
        'receiver_id': target_id,
        'start_time': datetime.utcnow(),
        'type': call_type,
        'log_id': call_log.id
    }
    
    # Notify admins of new call
    admin_users = User.query.filter_by(is_admin=True).all()
    for admin in admin_users:
        socketio.emit('new_active_call', {
            'call_id': call_id,
            'caller': User.query.get(caller_id).username,
            'receiver': User.query.get(target_id).username,
            'type': call_type
        }, room=str(admin.id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need admin privileges to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    # Get statistics
    total_users = User.query.count()
    new_users_today = User.query.filter(
        User.created_at >= datetime.utcnow().date()
    ).count()
    
    messages_today = Message.query.filter(
        Message.timestamp >= datetime.utcnow().date()
    ).count()
    
    message_rate = Message.query.filter(
        Message.timestamp >= datetime.utcnow() - timedelta(hours=1)
    ).count()
    
    active_users = User.query.filter(
        User.last_seen >= datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    # Get recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    stats = {
        'total_users': total_users,
        'new_users_today': new_users_today,
        'messages_today': messages_today,
        'message_rate': message_rate,
        'active_users': active_users,
        'reports': 0,  # Add report functionality
        'unresolved_reports': 0
    }
    
    return render_template('admin/dashboard.html', 
                         stats=stats,
                         recent_users=recent_users)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False)
    return render_template('admin/users.html', users=users)

@app.route('/admin/messages')
@login_required
@admin_required
def admin_messages():
    page = request.args.get('page', 1, type=int)
    messages = Message.query.order_by(Message.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False)
    return render_template('admin/messages.html', messages=messages)

@app.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'delete':
            db.session.delete(user)
        elif action == 'toggle_admin':
            user.is_admin = not user.is_admin
        elif action == 'reset_password':
            new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            user.set_password(new_password)
            flash(f'New password for {user.username}: {new_password}', 'success')
        
        db.session.commit()
        return redirect(url_for('admin_users'))
    
    return render_template('admin/user_detail.html', user=user)

@app.route('/admin/message/<int:message_id>', methods=['POST'])
@login_required
@admin_required
def admin_message(message_id):
    message = Message.query.get_or_404(message_id)
    action = request.form.get('action')
    
    if action == 'delete':
        db.session.delete(message)
        db.session.commit()
        flash('Message deleted successfully.', 'success')
    
    return redirect(url_for('admin_messages'))

@app.route('/admin_panel')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    
    view = request.args.get('view', 'dashboard')  # Set 'dashboard' as default view
    
    if view == 'users':
        page = request.args.get('page', 1, type=int)
        users = User.query.order_by(User.created_at.desc()).paginate(
            page=page, per_page=20, error_out=False)
        return render_template('admin/users.html', users=users)
        
    elif view == 'messages':
        page = request.args.get('page', 1, type=int)
        messages = Message.query.order_by(Message.timestamp.desc()).paginate(
            page=page, per_page=50, error_out=False)
        return render_template('admin/messages.html', messages=messages)

    elif view == 'calls':
        # Get call statistics
        call_logs = CallLog.query.all()
        active_call_list = []
        
        for call_id, call_data in active_calls.items():
            caller = User.query.get(call_data['caller_id'])
            receiver = User.query.get(call_data['receiver_id'])
            duration = int((datetime.utcnow() - call_data['start_time']).total_seconds())
            
            active_call_list.append({
                'call_id': call_id,
                'caller': caller.username,
                'receiver': receiver.username,
                'type': call_data['type'],
                'duration': duration,
                'start_time': call_data['start_time']
            })
            
        return render_template('admin/calls.html',
            call_logs=call_logs,
            active_calls=active_call_list
        )

    # Default view (dashboard)
    # Get search history with user info
    search_history = db.session.query(SearchHistory, User)\
        .join(User)\
        .order_by(SearchHistory.timestamp.desc())\
        .limit(100)\
        .all()
    
    # Get active calls
    active_calls_list = []
    for call_id, call_data in active_calls.items():
        caller = User.query.get(call_data['caller_id'])
        receiver = User.query.get(call_data['receiver_id'])
        active_calls_list.append({
            'id': call_id,
            'caller': caller.username,
            'receiver': receiver.username,
            'type': call_data['type'],
            'duration': int((datetime.utcnow() - call_data['start_time']).total_seconds())
        })
    
    # Get statistics
    total_users = User.query.count()
    new_users_today = User.query.filter(
        User.created_at >= datetime.utcnow().date()
    ).count()
    
    messages_today = Message.query.filter(
        Message.timestamp >= datetime.utcnow().date()
    ).count()
    
    message_rate = Message.query.filter(
        Message.timestamp >= datetime.utcnow() - timedelta(hours=1)
    ).count()
    
    active_users = User.query.filter(
        User.last_seen >= datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    return render_template('admin/dashboard.html',
        search_history=search_history,
        active_calls=active_calls_list,
        stats={
            'total_users': total_users,
            'new_users_today': new_users_today,
            'messages_today': messages_today,
            'message_rate': message_rate,
            'active_users': active_users
        }
    )

@app.route('/admin/reset_password', methods=['POST'])
@login_required
def admin_reset_password():
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
        
    data = request.get_json()
    user_id = data.get('user_id')
    new_password = data.get('new_password')
    
    if not user_id or not new_password:
        return jsonify({'error': 'Missing required fields'}), 400
        
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    user.set_password(new_password)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/admin/call-stats')
@login_required
def admin_call_stats():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    
    # Get call statistics
    call_logs = CallLog.query.all()
    active_call_list = []
    
    for call_id, call_data in active_calls.items():
        caller = User.query.get(call_data['caller_id'])
        receiver = User.query.get(call_data['receiver_id'])
        duration = int((datetime.utcnow() - call_data['start_time']).total_seconds())
        
        active_call_list.append({
            'call_id': call_id,
            'caller': caller.username,
            'receiver': receiver.username,
            'type': call_data['type'],
            'duration': duration,
            'start_time': call_data['start_time']
        })
    
    return jsonify({
        'call_logs': [{
            'id': log.id,
            'caller': log.caller.username,
            'receiver': log.receiver.username,
            'start_time': log.start_time.isoformat(),
            'end_time': log.end_time.isoformat() if log.end_time else None,
            'duration': log.duration,
            'call_type': log.call_type
        } for log in call_logs],
        'active_calls': active_call_list
    })

@app.route('/admin/join-call/<call_id>')
@login_required
def admin_join_call(call_id):
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    
    if call_id not in active_calls:
        return jsonify({'error': 'Call not found'}), 404
    
    call_data = active_calls[call_id]
    
    # Add admin to the call's WebRTC signaling
    socketio.emit('admin_joined', {
        'admin_id': current_user.id
    }, room=str(call_data['caller_id']))
    socketio.emit('admin_joined', {
        'admin_id': current_user.id
    }, room=str(call_data['receiver_id']))
    
    return jsonify({
        'status': 'success',
        'call_type': call_data['type']
    })

@app.route('/admin/clear_user_history/<int:user_id>')
@login_required
def clear_user_history(user_id):
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Clear user's search history
        SearchHistory.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        flash('User search history cleared successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error clearing search history.', 'danger')
        logger.error(f"Error clearing search history for user {user_id}: {str(e)}")
    
    return redirect(url_for('admin_panel'))

# File upload configurations
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads', 'avatars')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Create upload directories if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    try:
        if 'avatar' not in request.files:
            app.logger.error('No file part in request')
            return jsonify({'success': False, 'error': 'No file provided'})
        
        file = request.files['avatar']
        if file.filename == '':
            app.logger.error('No selected file')
            return jsonify({'success': False, 'error': 'No file selected'})
        
        if file and allowed_file(file.filename):
            # Delete old avatar if it exists
            if current_user.avatar_url:
                old_avatar_path = os.path.join(app.root_path, 'static', current_user.avatar_url.lstrip('/'))
                if os.path.exists(old_avatar_path):
                    try:
                        os.remove(old_avatar_path)
                    except Exception as e:
                        app.logger.error(f'Error deleting old avatar: {str(e)}')
            
            # Generate secure filename with timestamp
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = secure_filename(f"avatar_{current_user.id}_{timestamp}_{file.filename}")
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            
            # Save new avatar
            file.save(file_path)
            
            # Update user's avatar URL in database
            avatar_url = f'/static/uploads/avatars/{filename}'
            current_user.avatar_url = avatar_url
            db.session.commit()
            
            app.logger.info(f'Successfully uploaded avatar for user {current_user.id}')
            return jsonify({
                'success': True,
                'url': avatar_url
            })
        
        app.logger.error('Invalid file type')
        return jsonify({'success': False, 'error': 'Invalid file type'})
        
    except Exception as e:
        app.logger.error(f'Error in upload_avatar: {str(e)}')
        return jsonify({'success': False, 'error': 'Server error occurred'})

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/message/react', methods=['POST'])
@login_required
def react_to_message():
    data = request.get_json()
    message_id = data.get('message_id')
    reaction = data.get('reaction')
    
    if not message_id or not reaction:
        return jsonify({'error': 'Missing required fields'}), 400
        
    try:
        # Check if user already reacted
        existing_reaction = MessageReaction.query.filter_by(
            message_id=message_id,
            user_id=current_user.id
        ).first()
        
        if existing_reaction:
            if existing_reaction.reaction == reaction:
                db.session.delete(existing_reaction)
                db.session.commit()
                return jsonify({'status': 'removed'})
            else:
                existing_reaction.reaction = reaction
                existing_reaction.timestamp = datetime.utcnow()
        else:
            new_reaction = MessageReaction(
                message_id=message_id,
                user_id=current_user.id,
                reaction=reaction
            )
            db.session.add(new_reaction)
            
        db.session.commit()
        return jsonify({'status': 'success'})
        
    except Exception as e:
        app.logger.error(f"Reaction error: {str(e)}")
        return jsonify({'error': 'Failed to add reaction'}), 500

@app.route('/message/pin', methods=['POST'])
@login_required
def pin_message():
    data = request.get_json()
    message_id = data.get('message_id')
    
    if not message_id:
        return jsonify({'error': 'Message ID required'}), 400
        
    try:
        message = Message.query.get(message_id)
        if not message:
            return jsonify({'error': 'Message not found'}), 404
            
        # Check permissions if it's a group message
        if message.group_id:
            member = GroupMember.query.filter_by(
                group_id=message.group_id,
                user_id=current_user.id
            ).first()
            if not member or member.role not in ['admin', 'moderator']:
                return jsonify({'error': 'Permission denied'}), 403
                
        message.is_pinned = not message.is_pinned
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'pinned': message.is_pinned
        })
        
    except Exception as e:
        app.logger.error(f"Pin message error: {str(e)}")
        return jsonify({'error': 'Failed to pin message'}), 500

@app.route('/message/translate', methods=['POST'])
@login_required
def translate_message():
    data = request.get_json()
    message_id = data.get('message_id')
    target_language = data.get('target_language', current_user.preferred_language or 'en')
    
    if not message_id:
        return jsonify({'error': 'Message ID required'}), 400
        
    try:
        message = Message.query.get(message_id)
        if not message:
            return jsonify({'error': 'Message not found'}), 404
            
        # Only translate if not already translated to this language
        if not message.is_translated or message.original_language != target_language:
            # Detect language if not set
            if not message.original_language:
                message.original_language = translator.detect(message.content).lang
                message.original_content = message.content
                
            # Translate content
            translation = translator.translate(
                message.content,
                dest=target_language,
                src=message.original_language
            )
            
            message.content = translation.text
            message.is_translated = True
            db.session.commit()
            
        return jsonify({
            'status': 'success',
            'translated_text': message.content,
            'original_text': message.original_content,
            'from_language': message.original_language,
            'to_language': target_language
        })
        
    except Exception as e:
        app.logger.error(f"Translation error: {str(e)}")
        return jsonify({'error': 'Translation failed'}), 500

@app.route('/group/create', methods=['POST'])
@login_required
def create_group():
    data = request.get_json()
    name = data.get('name')
    description = data.get('description', '')
    
    if not name:
        return jsonify({'error': 'Group name required'}), 400
        
    try:
        # Generate unique invite code
        while True:
            invite_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if not Group.query.filter_by(invite_code=invite_code).first():
                break
                
        group = Group(
            name=name,
            description=description,
            invite_code=invite_code
        )
        db.session.add(group)
        db.session.flush()
        
        # Add creator as admin
        member = GroupMember(
            user_id=current_user.id,
            group_id=group.id,
            role='admin'
        )
        db.session.add(member)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'group_id': group.id,
            'invite_code': invite_code
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Group creation error: {str(e)}")
        return jsonify({'error': 'Failed to create group'}), 500

@app.route('/group/join/<invite_code>', methods=['POST'])
@login_required
def join_group(invite_code):
    try:
        group = Group.query.filter_by(invite_code=invite_code).first()
        if not group:
            return jsonify({'error': 'Invalid invite code'}), 404
            
        # Check if already a member
        existing_member = GroupMember.query.filter_by(
            group_id=group.id,
            user_id=current_user.id
        ).first()
        
        if existing_member:
            return jsonify({'error': 'Already a member'}), 400
            
        member = GroupMember(
            user_id=current_user.id,
            group_id=group.id,
            role='member'
        )
        db.session.add(member)
        db.session.commit()
        
        return jsonify({'status': 'success', 'group_id': group.id})
        
    except Exception as e:
        app.logger.error(f"Group join error: {str(e)}")
        return jsonify({'error': 'Failed to join group'}), 500

@app.route('/group/<int:group_id>/members', methods=['GET'])
@login_required
def get_group_members(group_id):
    try:
        members = GroupMember.query.filter_by(group_id=group_id).all()
        return jsonify({
            'members': [{
                'user_id': m.user_id,
                'username': User.query.get(m.user_id).username,
                'role': m.role,
                'joined_at': m.joined_at.isoformat()
            } for m in members]
        })
    except Exception as e:
        app.logger.error(f"Get members error: {str(e)}")
        return jsonify({'error': 'Failed to get members'}), 500

@app.route('/typing-status', methods=['POST'])
@login_required
def update_typing_status():
    data = request.get_json()
    status = data.get('status')  # 'typing', 'idle'
    target_id = data.get('target_id')  # group_id or user_id
    
    try:
        current_user.typing_status = status
        current_user.typing_in = target_id if status == 'typing' else None
        db.session.commit()
        
        # Broadcast typing status via WebSocket
        socketio.emit('typing_update', {
            'user_id': current_user.id,
            'username': current_user.username,
            'status': status,
            'target_id': target_id
        }, room=str(target_id))
        
        return jsonify({'status': 'success'})
        
    except Exception as e:
        app.logger.error(f"Typing status error: {str(e)}")
        return jsonify({'error': 'Failed to update typing status'}), 500

@app.route('/message/thread', methods=['POST'])
@login_required
def create_thread_reply():
    data = request.get_json()
    parent_id = data.get('parent_id')
    content = data.get('content')
    
    if not parent_id or not content:
        return jsonify({'error': 'Missing required fields'}), 400
        
    try:
        parent_message = Message.query.get(parent_id)
        if not parent_message:
            return jsonify({'error': 'Parent message not found'}), 404
            
        reply = Message(
            content=content,
            user_id=current_user.id,
            username=current_user.username,
            chat_type=parent_message.chat_type,
            parent_id=parent_id,
            group_id=parent_message.group_id,
            recipient_id=parent_message.recipient_id
        )
        db.session.add(reply)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message_id': reply.id
        })
        
    except Exception as e:
        app.logger.error(f"Thread reply error: {str(e)}")
        return jsonify({'error': 'Failed to create reply'}), 500

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required', 'error')
        return redirect(url_for('settings'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('settings'))
    
    user = User.query.get(current_user.id)
    if not user.check_password(current_password):
        flash('Current password is incorrect', 'error')
        return redirect(url_for('settings'))
    
    user.set_password(new_password)
    db.session.commit()
    flash('Password successfully updated', 'success')
    return redirect(url_for('settings'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        try:
            current_user.bio = request.form.get('bio', '')
            current_user.theme = request.form.get('theme', 'light')
            current_user.notification_sound = 'notification_sound' in request.form
            current_user.desktop_notifications = 'desktop_notifications' in request.form
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
            
        except Exception as e:
            app.logger.error(f"Profile update error: {str(e)}")
            return jsonify({'error': 'Failed to update profile'}), 500
    
    # Get counts for profile stats
    friends_count = len(current_user.get_friends())
    messages_count = Message.query.filter_by(sender_id=current_user.id).count()
    groups_count = len(current_user.groups)
    
    return render_template('profile.html', 
                         friends_count=friends_count,
                         messages_count=messages_count,
                         groups_count=groups_count)

@app.route('/profile/avatar', methods=['POST'])
@login_required
def update_avatar():
    if 'avatar' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
        
    try:
        filename = secure_filename(file.filename)
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"avatar_{current_user.id}_{timestamp}_{filename}"
        
        # Save file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        file.save(file_path)
        
        # Update user's profile picture
        current_user.profile_picture = url_for('uploaded_file', filename=unique_filename)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'url': current_user.profile_picture
        })
        
    except Exception as e:
        app.logger.error(f"Avatar update error: {str(e)}")
        return jsonify({'error': 'Failed to update avatar'}), 500

@app.route('/notifications')
@login_required
def notifications():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('notifications.html', notifications=notifications)

@app.route('/notifications/mark-read', methods=['POST'])
@login_required
def mark_notifications_read():
    try:
        notification_ids = request.get_json().get('notification_ids', [])
        
        if notification_ids:
            Notification.query.filter(
                Notification.id.in_(notification_ids),
                Notification.user_id == current_user.id
            ).update({Notification.read: True}, synchronize_session=False)
        else:
            # Mark all as read if no specific IDs provided
            Notification.query.filter_by(
                user_id=current_user.id,
                read=False
            ).update({Notification.read: True}, synchronize_session=False)
            
        db.session.commit()
        return jsonify({'status': 'success'})
        
    except Exception as e:
        app.logger.error(f"Mark notifications error: {str(e)}")
        return jsonify({'error': 'Failed to mark notifications as read'}), 500

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        if query:
            # Track search history
            search_history = SearchHistory(user_id=current_user.id, query=query)
            db.session.add(search_history)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error saving search history: {str(e)}")

            # Perform search
            users = User.query.filter(
                User.username.ilike(f'%{query}%'),
                User.id != current_user.id
            ).all()
            return jsonify([{
                'id': user.id,
                'username': user.username,
                'status': user.status,
                'is_friend': current_user.is_friend_with(user)
            } for user in users])
    return jsonify([])

@app.route('/message/forward', methods=['POST'])
@login_required
def forward_message():
    data = request.get_json()
    message_id = data.get('message_id')
    target_id = data.get('target_id')
    chat_type = data.get('chat_type')  # 'user' or 'group'
    
    if not message_id or not target_id or not chat_type:
        return jsonify({'error': 'Missing required fields'}), 400
        
    try:
        original_message = Message.query.get(message_id)
        if not original_message:
            return jsonify({'error': 'Message not found'}), 404
            
        # Create new message
        new_message = Message(
            content=original_message.content,
            user_id=current_user.id,
            username=current_user.username,
            chat_type=chat_type,
            message_type=original_message.message_type,
            file_url=original_message.file_url,
            file_type=original_message.file_type,
            file_name=original_message.file_name,
            file_size=original_message.file_size,
            code_language=original_message.code_language
        )
        
        if chat_type == 'user':
            new_message.recipient_id = target_id
        else:
            new_message.group_id = target_id
            
        db.session.add(new_message)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message_id': new_message.id
        })
        
    except Exception as e:
        app.logger.error(f"Forward message error: {str(e)}")
        return jsonify({'error': 'Failed to forward message'}), 500

@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if Admin.query.filter_by(username=username).first():
            flash('Admin username already exists')
            return redirect(url_for('register_admin'))

        admin = Admin(username=username)
        admin.set_password(password)

        db.session.add(admin)
        db.session.commit()

        flash('Admin registration successful')
        return redirect(url_for('login'))

    return render_template('register_admin.html')

@app.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin = Admin.query.filter_by(username=username).first()
        if admin is None or not admin.check_password(password):
            flash('Invalid admin credentials')
            return redirect(url_for('login_admin'))

        session['admin_authenticated'] = True
        flash('Admin login successful')
        return redirect(url_for('admin_panel'))

    return render_template('login_admin.html')

@app.route('/check_messages')
@login_required
def check_messages():
    try:
        # Get unread messages for private chats
        private_messages = Message.query.filter(
            Message.recipient_id == current_user.id,
            Message.chat_type == 'private',
            Message.read == False
        ).order_by(Message.timestamp.desc()).all()

        # Get unread messages from groups
        group_messages = Message.query.join(
            GroupMember, 
            GroupMember.group_id == Message.group_id
        ).filter(
            GroupMember.user_id == current_user.id,
            Message.chat_type == 'group',
            Message.sender_id != current_user.id,
            Message.read == False
        ).order_by(Message.timestamp.desc()).all()

        # Combine and format messages
        unread_messages = []
        for msg in private_messages + group_messages:
            sender = User.query.get(msg.sender_id)
            message_data = {
                'id': msg.id,
                'content': msg.content,
                'sender_id': msg.sender_id,
                'sender_name': sender.username if sender else 'Unknown',
                'timestamp': msg.timestamp.isoformat(),
                'chat_type': msg.chat_type,
                'group_id': msg.group_id,
                'message_type': msg.message_type
            }
            unread_messages.append(message_data)

        return jsonify({
            'status': 'success',
            'unread_count': len(unread_messages),
            'messages': unread_messages
        })

    except Exception as e:
        logger.error(f"Error in check_messages: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    chat_type = request.form.get('chat_type')
    content = request.form.get('message')
    
    if not content:
        flash('Message cannot be empty')
        return redirect(request.referrer)
    
    message = Message(
        content=content,
        user_id=current_user.id,
        username=current_user.username,
        chat_type=chat_type
    )
    
    if chat_type == 'private':
        recipient_id = int(request.form.get('recipient_id'))
        message.recipient_id = recipient_id
    else:
        group_id = int(request.form.get('group_id'))
        message.group_id = group_id
    
    db.session.add(message)
    db.session.commit()
    
    # Return JSON response for AJAX requests
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'status': 'success',
            'message': {
                'id': message.id,
                'content': message.content,
                'timestamp': message.timestamp.isoformat(),
                'sender_id': message.user_id,
                'sender_name': message.username,
                'chat_type': message.chat_type,
                'group_id': message.group_id if message.chat_type == 'group' else None
            }
        })
    
    return redirect(request.referrer)

@app.route('/add_to_group/<int:group_id>', methods=['POST'])
@login_required
def add_to_group(group_id):
    friend_id = int(request.form['friend_id'])
    group = Group.query.get_or_404(group_id)
    
    # Verify the current user is a member of the group
    is_member = GroupMember.query.filter_by(
        user_id=current_user.id, group_id=group_id).first()
    if not is_member:
        flash('You are not a member of this group')
        return redirect(url_for('chat', group_id=group_id))
    
    # Check if user is already in group
    existing_member = GroupMember.query.filter_by(
        user_id=friend_id, group_id=group_id).first()
    
    if not existing_member:
        member = GroupMember(user_id=friend_id, group_id=group_id)
        db.session.add(member)
        db.session.commit()
        
        # Add system message about new member
        message = Message(
            content=f"{User.query.get(friend_id).username} has joined the group",
            user_id=current_user.id,
            username="System",
            chat_type='group',
            group_id=group_id
        )
        db.session.add(message)
        db.session.commit()
        
        flash('Friend added to group')
    else:
        flash('Friend is already in the group')
    
    return redirect(url_for('chat', group_id=group_id))

@app.route('/request_friend_from_group/<int:group_id>/<int:user_id>')
@login_required
def request_friend_from_group(group_id, user_id):
    # Check if already friends or request exists
    existing_request = Friend.query.filter(
        ((Friend.user_id == current_user.id) & (Friend.friend_id == user_id)) |
        ((Friend.user_id == user_id) & (Friend.friend_id == current_user.id))
    ).first()
    
    if existing_request:
        flash('Friend request already exists or you are already friends')
    else:
        friend_request = Friend(
            user_id=current_user.id,
            friend_id=user_id,
            status='pending'
        )
        db.session.add(friend_request)
        db.session.commit()
        flash('Friend request sent')
    
    return redirect(url_for('chat', group_id=group_id))

@app.route('/upload', methods=['POST'])
@login_required
@limiter.limit("1000000 per minute")  # Effectively unlimited
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        return jsonify({'message': 'File uploaded successfully', 'filename': filename})

@app.route('/unfriend/<int:friend_id>')
@login_required
def unfriend(friend_id):
    Friend.query.filter(
        ((Friend.user_id == current_user.id) & (Friend.friend_id == friend_id)) |
        ((Friend.user_id == friend_id) & (Friend.friend_id == current_user.id))
    ).delete()
    db.session.commit()
    flash('Friend removed')
    return redirect(url_for('friends'))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/friends')
@login_required
def friends():
    # Get friend requests sent by current user
    sent_requests = Friend.query.filter_by(
        user_id=current_user.id,
        status='pending'
    ).all()
    
    # Get friend requests received by current user
    received_requests = Friend.query.filter_by(
        friend_id=current_user.id,
        status='pending'
    ).all()
    
    # Get accepted friends
    friends = Friend.query.filter(
        ((Friend.user_id == current_user.id) | (Friend.friend_id == current_user.id)) &
        (Friend.status == 'accepted')
    ).all()
    
    return render_template('friends.html',
                         sent_requests=sent_requests,
                         received_requests=received_requests,
                         friends=friends)

@app.route('/send_friend_request/<int:user_id>')
@login_required
def send_friend_request(user_id):
    if user_id == current_user.id:
        flash('You cannot send a friend request to yourself')
        return redirect(url_for('friends'))
        
    # Check if request already exists
    existing_request = Friend.query.filter(
        ((Friend.user_id == current_user.id) & (Friend.friend_id == user_id)) |
        ((Friend.user_id == user_id) & (Friend.friend_id == current_user.id))
    ).first()
    
    if existing_request:
        flash('Friend request already exists')
        return redirect(url_for('friends'))
        
    friend_request = Friend(
        user_id=current_user.id,
        friend_id=user_id,
        status='pending'
    )
    db.session.add(friend_request)
    db.session.commit()
    
    flash('Friend request sent')
    return redirect(url_for('friends'))

@app.route('/accept_friend_request/<int:request_id>')
@login_required
def accept_friend_request(request_id):
    friend_request = Friend.query.get_or_404(request_id)
    
    if friend_request.friend_id != current_user.id:
        flash('Access denied')
        return redirect(url_for('friends'))
        
    friend_request.status = 'accepted'
    db.session.commit()
    
    flash('Friend request accepted')
    return redirect(url_for('friends'))

@app.route('/reject_friend_request/<int:request_id>')
@login_required
def reject_friend_request(request_id):
    friend_request = Friend.query.get_or_404(request_id)
    
    if friend_request.friend_id != current_user.id:
        flash('Access denied')
        return redirect(url_for('friends'))
        
    friend_request.status = 'rejected'
    db.session.commit()
    
    flash('Friend request rejected')
    return redirect(url_for('friends'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("1000000 per minute")  # Effectively unlimited
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        while True:
            public_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            if not User.query.filter_by(public_id=public_id).first():
                break

        user = User(username=username, public_id=public_id)
        user.set_password(password)

        # Make the first user an admin
        if User.query.count() == 0:
            user.is_admin = True

        db.session.add(user)
        db.session.commit()

        flash('Registration successful')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("1000000 per minute")  # Effectively unlimited
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            add_session(user.id)
            
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('chat')
                
            return redirect(next_page)
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html', active_sessions=get_current_sessions())

@app.route('/logout/<int:user_id>')
def logout_session(user_id):
    """Logout specific session"""
    remove_session(user_id)
    if current_user.is_authenticated and current_user.id == user_id:
        logout_user()
    return redirect(url_for('login'))

@app.route('/switch/<int:user_id>')
def switch_account(user_id):
    """Switch to another logged in account"""
    if user_id in get_current_sessions():
        user = User.query.get(user_id)
        if user:
            logout_user()
            login_user(user)
            return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    groups = Group.query.join(GroupMember).filter(GroupMember.user_id == current_user.id).all()
    friends = User.query.join(Friend, 
        ((Friend.user_id == User.id) & (Friend.friend_id == current_user.id)) |
        ((Friend.user_id == current_user.id) & (Friend.friend_id == User.id))
    ).filter(Friend.status == 'accepted').all()
    
    selected_friend = request.args.get('friend_id', type=int)
    selected_group = request.args.get('group_id', type=int)
    
    if selected_friend:
        messages = Message.query.filter(
            ((Message.user_id == current_user.id) & (Message.recipient_id == selected_friend)) |
            ((Message.user_id == selected_friend) & (Message.recipient_id == current_user.id))
        ).order_by(Message.timestamp.desc()).limit(100).all()
        uploads = Upload.query.filter(
            ((Upload.user_id == current_user.id) & (Upload.recipient_id == selected_friend)) |
            ((Upload.user_id == selected_friend) & (Upload.recipient_id == current_user.id))
        ).order_by(Upload.timestamp.desc()).all()
        chat_type = 'private'
        chat_target = User.query.get(selected_friend)
    elif selected_group:
        messages = Message.query.filter_by(group_id=selected_group).order_by(Message.timestamp.desc()).limit(100).all()
        uploads = Upload.query.filter_by(group_id=selected_group).order_by(Upload.timestamp.desc()).all()
        chat_type = 'group'
        chat_target = Group.query.get(selected_group)
        group_members = User.query.join(GroupMember).filter(GroupMember.group_id == selected_group).all()
        potential_members = [f for f in friends if f not in group_members]
    else:
        messages = []
        uploads = []
        chat_type = None
        chat_target = None
        group_members = []
        potential_members = []
    
    return render_template('chat.html', 
                         messages=messages,
                         uploads=uploads,
                         groups=groups,
                         friends=friends,
                         chat_type=chat_type,
                         chat_target=chat_target,
                         group_members=group_members if selected_group else [],
                         potential_members=potential_members if selected_group else [])

# Message scheduling
@app.route('/message/schedule', methods=['POST'])
@login_required
def schedule_message():
    data = request.get_json()
    content = data.get('content')
    schedule_time = data.get('schedule_time')
    chat_type = data.get('chat_type')
    target_id = data.get('target_id')
    
    if not all([content, schedule_time, chat_type, target_id]):
        return jsonify({'error': 'Missing required fields'}), 400
        
    try:
        schedule_dt = datetime.fromisoformat(schedule_time)
        if schedule_dt <= datetime.utcnow():
            return jsonify({'error': 'Schedule time must be in the future'}), 400
            
        scheduled_message = ScheduledMessage(
            content=content,
            user_id=current_user.id,
            username=current_user.username,
            chat_type=chat_type,
            schedule_time=schedule_dt
        )
        
        if chat_type == 'user':
            scheduled_message.recipient_id = target_id
        else:
            scheduled_message.group_id = target_id
            
        db.session.add(scheduled_message)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Message scheduled successfully'
        })
        
    except Exception as e:
        app.logger.error(f"Schedule message error: {str(e)}")
        return jsonify({'error': 'Failed to schedule message'}), 500

# Message drafts
@app.route('/message/draft', methods=['POST'])
@login_required
def save_draft():
    data = request.get_json()
    content = data.get('content')
    chat_type = data.get('chat_type')
    target_id = data.get('target_id')
    
    if not all([content, chat_type, target_id]):
        return jsonify({'error': 'Missing required fields'}), 400
        
    try:
        draft = MessageDraft(
            content=content,
            user_id=current_user.id,
            chat_type=chat_type
        )
        
        if chat_type == 'user':
            draft.recipient_id = target_id
        else:
            draft.group_id = target_id
            
        db.session.add(draft)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'draft_id': draft.id
        })
        
    except Exception as e:
        app.logger.error(f"Save draft error: {str(e)}")
        return jsonify({'error': 'Failed to save draft'}), 500

@app.route('/message/drafts', methods=['GET'])
@login_required
def get_drafts():
    chat_type = request.args.get('chat_type')
    target_id = request.args.get('target_id')
    
    try:
        query = MessageDraft.query.filter_by(user_id=current_user.id)
        
        if chat_type == 'user':
            query = query.filter_by(recipient_id=target_id)
        elif chat_type == 'group':
            query = query.filter_by(group_id=target_id)
            
        drafts = query.order_by(MessageDraft.created_at.desc()).all()
        
        return jsonify({
            'drafts': [{
                'id': d.id,
                'content': d.content,
                'created_at': d.created_at.isoformat()
            } for d in drafts]
        })
        
    except Exception as e:
        app.logger.error(f"Get drafts error: {str(e)}")
        return jsonify({'error': 'Failed to get drafts'}), 500

# Message templates
@app.route('/message/templates', methods=['GET', 'POST'])
@login_required
def message_templates():
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        content = data.get('content')
        
        if not name or not content:
            return jsonify({'error': 'Name and content are required'}), 400
            
        try:
            template = MessageTemplate(
                name=name,
                content=content,
                user_id=current_user.id
            )
            db.session.add(template)
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'template_id': template.id
            })
            
        except Exception as e:
            app.logger.error(f"Save template error: {str(e)}")
            return jsonify({'error': 'Failed to save template'}), 500
            
    try:
        templates = MessageTemplate.query.filter_by(user_id=current_user.id).all()
        return jsonify({
            'templates': [{
                'id': t.id,
                'name': t.name,
                'content': t.content
            } for t in templates]
        })
        
    except Exception as e:
        app.logger.error(f"Get templates error: {str(e)}")
        return jsonify({'error': 'Failed to get templates'}), 500

# Message statistics
@app.route('/statistics', methods=['GET'])
@login_required
def get_statistics():
    try:
        # Get date range
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        if start_date:
            start_date = datetime.fromisoformat(start_date)
        else:
            start_date = datetime.utcnow() - timedelta(days=30)
            
        if end_date:
            end_date = datetime.fromisoformat(end_date)
        else:
            end_date = datetime.utcnow()
            
        # Message counts
        message_query = Message.query.filter(
            Message.user_id == current_user.id,
            Message.timestamp.between(start_date, end_date)
        )
        
        total_messages = message_query.count()
        direct_messages = message_query.filter_by(chat_type='user').count()
        group_messages = message_query.filter_by(chat_type='group').count()
        
        # Media statistics
        media_stats = {
            'images': message_query.filter_by(message_type='image').count(),
            'videos': message_query.filter_by(message_type='video').count(),
            'files': message_query.filter_by(message_type='file').count(),
            'code_snippets': message_query.filter_by(message_type='code').count()
        }
        
        # Activity by hour
        activity_by_hour = db.session.query(
            func.extract('hour', Message.timestamp).label('hour'),
            func.count(Message.id).label('count')
        ).filter(
            Message.user_id == current_user.id,
            Message.timestamp.between(start_date, end_date)
        ).group_by('hour').all()
        
        # Most active chats
        active_chats = db.session.query(
            case(
                (Message.chat_type == 'user', User.username),
                else_=Group.name
            ).label('chat_name'),
            func.count(Message.id).label('message_count')
        ).outerjoin(
            User, Message.recipient_id == User.id
        ).outerjoin(
            Group, Message.group_id == Group.id
        ).filter(
            Message.user_id == current_user.id,
            Message.timestamp.between(start_date, end_date)
        ).group_by('chat_name').order_by(desc('message_count')).limit(5).all()
        
        return jsonify({
            'total_messages': total_messages,
            'direct_messages': direct_messages,
            'group_messages': group_messages,
            'media_stats': media_stats,
            'activity_by_hour': [{
                'hour': hour,
                'count': count
            } for hour, count in activity_by_hour],
            'active_chats': [{
                'name': name,
                'count': count
            } for name, count in active_chats]
        })
        
    except Exception as e:
        app.logger.error(f"Get statistics error: {str(e)}")
        return jsonify({'error': 'Failed to get statistics'}), 500

@app.route('/detect_faces', methods=['POST'])
@login_required
def detect_faces():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type'}), 400
        
        # Read the image file
        filestr = file.read()
        nparr = np.frombuffer(filestr, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        # Load the face cascade classifier
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        
        # Convert to grayscale
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Detect faces
        faces = face_cascade.detectMultiScale(
            gray,
            scaleFactor=1.1,
            minNeighbors=5,
            minSize=(30, 30)
        )
        
        # Convert faces to list of coordinates
        face_list = []
        for (x, y, w, h) in faces:
            face_list.append({
                'x': int(x),
                'y': int(y),
                'width': int(w),
                'height': int(h)
            })
        
        return jsonify({
            'faces': face_list,
            'count': len(face_list)
        })
        
    except Exception as e:
        app.logger.error(f"Face detection error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to process image'}), 500

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                             'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/private_browse')
@login_required
def private_browse():
    session['private_mode'] = True
    return redirect(url_for('index'))

@app.route('/toggle_private_mode')
@login_required
def toggle_private_mode():
    session['private_mode'] = not session.get('private_mode', False)
    return redirect(request.referrer or url_for('index'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        try:
            # Get form data
            email = request.form.get('email')
            bio = request.form.get('bio')
            theme = request.form.get('theme')
            notification_sound = 'notification_sound' in request.form
            desktop_notifications = 'desktop_notifications' in request.form
            message_preview = 'message_preview' in request.form
            read_receipts = 'read_receipts' in request.form
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            # Update user settings
            current_user.email = email
            current_user.bio = bio
            current_user.theme = theme
            current_user.notification_sound = notification_sound
            current_user.desktop_notifications = desktop_notifications
            current_user.message_preview = message_preview
            current_user.read_receipts = read_receipts

            # Handle password change if requested
            if current_password and new_password and confirm_password:
                if not current_user.check_password(current_password):
                    flash('Current password is incorrect', 'error')
                    return redirect(url_for('settings'))
                if new_password != confirm_password:
                    flash('New passwords do not match', 'error')
                    return redirect(url_for('settings'))
                current_user.set_password(new_password)
                flash('Password updated successfully', 'success')

            db.session.commit()
            flash('Settings updated successfully', 'success')
            return redirect(url_for('settings'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Settings update error: {str(e)}", exc_info=True)
            flash('An error occurred while updating settings', 'error')
            return redirect(url_for('settings'))

    return render_template('settings.html')

@app.route('/api/users', methods=['GET'])
@login_required
def search_users():
    try:
        search_term = request.args.get('username', '').strip() or request.args.get('q', '').strip()
        if not search_term:
            return jsonify({'error': 'Please enter a username to search'}), 400

        # Search for users whose username or public_id contains the search term (case-insensitive)
        # Exclude the current user from results
        users = User.query.filter(
            db.or_(
                User.username.ilike(f'%{search_term}%'),
                User.public_id.ilike(f'%{search_term}%')
            ),
            User.id != current_user.id
        ).limit(10).all()

        if not users:
            return jsonify({
                'users': [],
                'message': 'No users found matching your search'
            })

        results = []
        for user in users:
            avatar_data = get_default_avatar(user.username)
            results.append({
                'id': user.id,
                'username': user.username,
                'public_id': user.public_id,
                'avatar_url': user.avatar_url,
                'avatar_color': avatar_data['color'],
                'avatar_initials': avatar_data['initials'],
                'is_friend': current_user.is_friend_with(user),
                'friend_request_sent': current_user.has_sent_friend_request_to(user),
                'friend_request_received': current_user.has_received_friend_request_from(user),
                'has_pending_request': bool(Friend.query.filter(
                    ((Friend.user_id == current_user.id) & (Friend.friend_id == user.id)) |
                    ((Friend.user_id == user.id) & (Friend.friend_id == current_user.id)),
                    Friend.status == 'pending'
                ).first())
            })

        # Save search history for searches with 3 or more characters
        if search_term and len(search_term) >= 3:
            search_history = SearchHistory(
                user_id=current_user.id,
                query=search_term
            )
            db.session.add(search_history)
            db.session.commit()

        return jsonify({'users': results})

    except Exception as e:
        app.logger.error(f'Error in search_users: {str(e)}')
        return jsonify({'error': 'An error occurred while searching for users'}), 500

@app.route('/add_friend/<int:user_id>')
@login_required
def add_friend(user_id):
    if user_id == current_user.id:
        flash('You cannot add yourself as a friend')
        return redirect(url_for('friends'))
        
    # Check if request already exists
    existing_request = Friend.query.filter(
        ((Friend.user_id == current_user.id) & (Friend.friend_id == user_id)) |
        ((Friend.user_id == user_id) & (Friend.friend_id == current_user.id))
    ).first()
    
    if existing_request:
        flash('Friend request already exists')
        return redirect(url_for('friends'))
        
    friend_request = Friend(
        user_id=current_user.id,
        friend_id=user_id,
        status='pending'
    )
    db.session.add(friend_request)
    db.session.commit()
    
    flash('Friend request sent')
    return redirect(url_for('friends'))

@app.route('/accept_friend/<int:request_id>')
@login_required
def accept_friend(request_id):
    friend_request = Friend.query.get_or_404(request_id)
    
    if friend_request.friend_id != current_user.id:
        flash('Access denied')
        return redirect(url_for('friends'))
        
    friend_request.status = 'accepted'
    db.session.commit()
    
    flash('Friend request accepted')
    return redirect(url_for('friends'))

@app.route('/reject_friend/<int:request_id>')
@login_required
def reject_friend(request_id):
    friend_request = Friend.query.get_or_404(request_id)
    
    if friend_request.friend_id != current_user.id:
        flash('Access denied')
        return redirect(url_for('friends'))
        
    friend_request.status = 'rejected'
    db.session.commit()
    
    flash('Friend request rejected')
    return redirect(url_for('friends'))

@app.route('/friend_requests')
@login_required
def friend_requests():
    # Get friend requests received by current user
    received_requests = Friend.query.filter_by(
        receiver_id=current_user.id,
        status='pending'
    ).all()
    
    # Get friend requests sent by current user
    sent_requests = Friend.query.filter_by(
        user_id=current_user.id,
        status='pending'
    ).all()
    
    return render_template('friend_requests.html',
                         received_requests=received_requests,
                         sent_requests=sent_requests)

@app.route('/friend_suggestions')
@login_required
def friend_suggestions():
    """Get friend suggestions based on mutual friends and interests"""
    # Get all friends of current user
    friends = current_user.get_friends()
    friend_ids = [f.id for f in friends]
    
    # Get friends of friends
    friends_of_friends = User.query.join(FriendRequest, db.or_(
        db.and_(FriendRequest.user_id == User.id, FriendRequest.receiver_id.in_(friend_ids)),
        db.and_(FriendRequest.receiver_id == User.id, FriendRequest.user_id.in_(friend_ids))
    )).filter(
        User.id != current_user.id,
        ~User.id.in_(friend_ids)
    ).distinct()
    
    # Format suggestions
    suggestions = []
    for user in friends_of_friends:
        mutual_friends = [f for f in user.get_friends() if f in friends]
        avatar_data = get_default_avatar(user.username)
        suggestions.append({
            'id': user.id,
            'username': user.username,
            'public_id': user.public_id,
            'avatar_color': avatar_data['color'],
            'avatar_initials': avatar_data['initials'],
            'mutual_friends': len(mutual_friends),
            'mutual_friend_names': [f.username for f in mutual_friends[:3]]
        })
    
    return jsonify(suggestions)

import signal
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info("Received shutdown signal")
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def cleanup():
    """Cleanup function to be called before shutdown"""
    try:
        with app.app_context():
            # Close database connections
            db.session.remove()
            db.engine.dispose()
        
        # Close any open files or resources
        logging.shutdown()
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")

def create_admin(username, password):
    """Create a new admin user"""
    try:
        # Check if user exists
        if User.query.filter_by(username=username).first():
            return False, "Username already exists"
            
        # Generate public ID
        while True:
            public_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            if not User.query.filter_by(public_id=public_id).first():
                break
                
        # Create user with admin privileges
        now = datetime.utcnow()
        user = User(
            username=username,
            public_id=public_id,
            is_admin=True,
            status='online',
            created_at=now,
            last_seen=now,
            theme='light',
            notification_sound=True,
            desktop_notifications=True,
            message_preview=True,
            read_receipts=True
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        return True, "Admin user created successfully"
        
    except Exception as e:
        db.session.rollback()
        return False, f"Failed to create admin: {str(e)}"

# Create initial admin user
with app.app_context():
    db.create_all()  # Create tables first
    success, message = create_admin('admin', 'admin123')
    if success:
        print("Created admin user - Username: admin, Password: admin123")
    else:
        print(f"Error creating admin: {message}")

if __name__ == '__main__':
    try:
        # Initialize database
        init_db()
        
        # Configure server
        server_config = {
            'host': '0.0.0.0',
            'port': 5000,
            'debug': True,
            'use_reloader': False,  # Disable reloader to prevent duplicate processes
        }
        
        # Configure Socket.IO
        socketio_config = {
            'logger': True,
            'engineio_logger': True,
            'cors_allowed_origins': '*',
            'ping_timeout': 60,
            'ping_interval': 25,
        }
        
        logger.info(f"Starting server on {server_config['host']}:{server_config['port']}")
        logger.info("Press Ctrl+C to stop the server")
        
        # Initialize SocketIO with its config
        socketio = SocketIO(app, **socketio_config)
        
        # Run the app with server config
        socketio.run(app, **server_config)
        
    except KeyboardInterrupt:
        logger.info("\nShutting down gracefully...")
    except Exception as e:
        logger.error(f"Error starting the application: {str(e)}")
    finally:
        cleanup()
        sys.exit(0)