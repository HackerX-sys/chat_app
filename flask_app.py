from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import random
import string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import ssl
import json
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Change this to a secure random key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# SSL context for HTTPS
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_default_certs()

# CORS configuration for Firebase Hosting
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    return response

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    public_id = db.Column(db.String(20), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # New admin flag
    friends = db.relationship('Friend', foreign_keys='Friend.user_id', backref='user', lazy=True)
    groups = db.relationship('GroupMember', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    chat_type = db.Column(db.String(20), nullable=False)  # 'group' or 'private'
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # For private messages
    group_id = db.Column(db.Integer, db.ForeignKey('chat_group.id'), nullable=True)  # For group messages

class ChatGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    members = db.relationship('GroupMember', backref='group', lazy=True)
    messages = db.relationship('Message', backref='group', lazy=True)

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('chat_group.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    original_filename = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    chat_type = db.Column(db.String(20), nullable=False)  # 'group' or 'private'
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # For private messages
    group_id = db.Column(db.Integer, db.ForeignKey('chat_group.id'), nullable=True)  # For group messages

class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
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
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Special admin credentials check
        if username == 'admin' and password == 'Jattwaad@16':
            user = User.query.filter_by(username='admin').first()
            if not user:
                user = User(
                    username='admin',
                    is_admin=True,
                    public_id='admin'
                )
                user.set_password('Jattwaad@16')
                db.session.add(user)
                db.session.commit()
            login_user(user)
            return redirect(url_for('admin_panel'))
        
        # Regular user login
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('chat'))
        
        flash('Invalid username or password')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    groups = ChatGroup.query.join(GroupMember).filter(GroupMember.user_id == current_user.id).all()
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
        chat_target = ChatGroup.query.get(selected_group)
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

@app.route('/check_messages')
@login_required
def check_messages():
    # Get the last check time from the session or use a default
    last_check = session.get('last_message_check', datetime.utcnow() - timedelta(seconds=10))
    
    # Update the last check time
    session['last_message_check'] = datetime.utcnow()
    
    # Query for new private messages
    private_messages = Message.query.filter(
        Message.timestamp > last_check,
        Message.chat_type == 'private',
        Message.recipient_id == current_user.id
    ).all()
    
    # Query for new group messages
    user_groups = [member.group_id for member in GroupMember.query.filter_by(user_id=current_user.id)]
    group_messages = Message.query.filter(
        Message.timestamp > last_check,
        Message.chat_type == 'group',
        Message.group_id.in_(user_groups),
        Message.user_id != current_user.id
    ).all()
    
    # Combine and format messages
    new_messages = []
    
    for msg in private_messages + group_messages:
        message_data = {
            'id': msg.id,
            'content': msg.content,
            'timestamp': msg.timestamp.isoformat(),
            'sender_id': msg.user_id,
            'sender_name': msg.username,
            'chat_type': msg.chat_type
        }
        
        if msg.chat_type == 'group':
            message_data['group_id'] = msg.group_id
        
        new_messages.append(message_data)
    
    return jsonify({
        'new_messages': new_messages
    })

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

@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    group_name = request.form['group_name']
    if group_name:
        group = ChatGroup(name=group_name, created_by=current_user.id)
        db.session.add(group)
        db.session.commit()
        
        # Add creator as first member
        member = GroupMember(user_id=current_user.id, group_id=group.id)
        db.session.add(member)
        db.session.commit()
        
        flash('Group created successfully')
    return redirect(url_for('chat'))

@app.route('/add_to_group/<int:group_id>', methods=['POST'])
@login_required
def add_to_group(group_id):
    friend_id = int(request.form['friend_id'])
    group = ChatGroup.query.get_or_404(group_id)
    
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
        friend_request = Friend(user_id=current_user.id, friend_id=user_id)
        db.session.add(friend_request)
        db.session.commit()
        flash('Friend request sent')
    
    return redirect(url_for('chat', group_id=group_id))

@app.route('/upload', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
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
    # Get friend requests
    friend_requests = Friend.query.filter_by(friend_id=current_user.id, status='pending').all()
    # Get accepted friends
    friends = Friend.query.filter(
        ((Friend.user_id == current_user.id) | (Friend.friend_id == current_user.id)) &
        (Friend.status == 'accepted')
    ).all()
    
    # Get the actual User objects for friends
    friend_list = []
    for friend in friends:
        if friend.user_id == current_user.id:
            friend_list.append(User.query.get(friend.friend_id))
        else:
            friend_list.append(User.query.get(friend.user_id))
    
    return render_template('friends.html', 
                         friend_requests=friend_requests, 
                         friends=friend_list,
                         current_user_id=current_user.public_id)

@app.route('/add_friend', methods=['POST'])
@login_required
def add_friend():
    friend_public_id = request.form['friend_public_id']
    friend = User.query.filter_by(public_id=friend_public_id).first()
    
    if not friend:
        flash('User not found')
        return redirect(url_for('friends'))
    
    if friend.id == current_user.id:
        flash('You cannot add yourself as a friend')
        return redirect(url_for('friends'))
    
    # Check if friend request already exists
    existing_request = Friend.query.filter(
        ((Friend.user_id == current_user.id) & (Friend.friend_id == friend.id)) |
        ((Friend.user_id == friend.id) & (Friend.friend_id == current_user.id))
    ).first()
    
    if existing_request:
        flash('Friend request already exists or you are already friends')
        return redirect(url_for('friends'))
    
    friend_request = Friend(user_id=current_user.id, friend_id=friend.id)
    db.session.add(friend_request)
    db.session.commit()
    
    flash('Friend request sent')
    return redirect(url_for('friends'))

@app.route('/accept_friend/<int:request_id>')
@login_required
def accept_friend(request_id):
    friend_request = Friend.query.get_or_404(request_id)
    
    if friend_request.friend_id != current_user.id:
        flash('Invalid friend request')
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
        flash('Invalid friend request')
        return redirect(url_for('friends'))
    
    db.session.delete(friend_request)
    db.session.commit()
    
    flash('Friend request rejected')
    return redirect(url_for('friends'))

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('chat'))
    
    # Get all messages with user info
    messages = Message.query.order_by(Message.timestamp.desc()).all()
    
    # Get all uploaded files
    uploaded_files = []
    upload_dir = os.path.join(app.root_path, 'uploads')
    if os.path.exists(upload_dir):
        for filename in os.listdir(upload_dir):
            file_path = os.path.join(upload_dir, filename)
            file_size = os.path.getsize(file_path)
            uploaded_files.append({
                'name': filename,
                'size': file_size,
                'date': datetime.fromtimestamp(os.path.getctime(file_path))
            })
    
    return render_template('admin.html', 
                         messages=messages, 
                         uploaded_files=uploaded_files)

@app.route('/admin/download/<filename>')
@login_required
def admin_download_file(filename):
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('chat'))
    
    upload_dir = os.path.join(app.root_path, 'uploads')
    return send_from_directory(upload_dir, filename, as_attachment=True)

@app.route('/admin/delete_file/<filename>')
@login_required
def admin_delete_file(filename):
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('chat'))
    
    file_path = os.path.join(app.root_path, 'uploads', filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f'File {filename} deleted successfully')
    else:
        flash(f'File {filename} not found')
    
    return redirect(url_for('admin_panel'))

@app.route('/make_admin/<int:user_id>')
@login_required
def make_admin(user_id):
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('chat'))
    
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    flash(f'User {user.username} is now an admin')
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    with app.app_context():
        # Add is_admin column if it doesn't exist
        inspector = db.inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('user')]
        
        if 'is_admin' not in columns:
            with db.engine.connect() as conn:
                conn.execute(db.text('ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT FALSE'))
                conn.commit()
        
        # Create tables if they don't exist
        db.create_all()
        
        # Ensure admin user exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                is_admin=True,
                public_id='admin'
            )
            admin.set_password('Jattwaad@16')
            db.session.add(admin)
            db.session.commit()
        elif not admin.is_admin:
            admin.is_admin = True
            db.session.commit()
            
    print("\nServer is running!")
    print("Access methods:")
    print("1. Local network: http://192.168.1.80:6969")
    print("2. Internet access: Use ngrok (starting...)")
    
    # Start ngrok in a separate process
    import subprocess
    try:
        ngrok_process = subprocess.Popen(['ngrok', 'http', '6969'], 
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
        print("Ngrok started successfully! Get your public URL at: http://localhost:4040")
    except Exception as e:
        print("Note: Ngrok not started:", str(e))
        print("To use ngrok, install it from: https://ngrok.com/download")
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=6969, debug=True)