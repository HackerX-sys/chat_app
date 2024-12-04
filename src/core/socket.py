from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import current_user
from datetime import datetime
from src.core.models import db, Message, User, Notification
from src.core.chat import send_message

socketio = SocketIO()

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        current_user.status = 'online'
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        emit('status_change', {
            'user_id': current_user.id,
            'status': 'online'
        }, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.status = 'offline'
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        emit('status_change', {
            'user_id': current_user.id,
            'status': 'offline'
        }, broadcast=True)

@socketio.on('join')
def handle_join(data):
    room = str(data.get('room'))
    join_room(room)
    emit('join_announcement', {
        'user': current_user.username,
        'room': room
    }, room=room)

@socketio.on('leave')
def handle_leave(data):
    room = str(data.get('room'))
    leave_room(room)
    emit('leave_announcement', {
        'user': current_user.username,
        'room': room
    }, room=room)

@socketio.on('new_message')
def handle_message(data):
    recipient_id = data.get('recipient_id')
    content = data.get('content')
    group_id = data.get('group_id')
    
    message = send_message(
        sender_id=current_user.id,
        recipient_id=recipient_id,
        content=content,
        group_id=group_id
    )
    
    # Create notification for recipient
    if recipient_id:
        notification = Notification(
            user_id=recipient_id,
            type='new_message',
            content=f'New message from {current_user.username}',
            related_id=message.id
        )
        db.session.add(notification)
        db.session.commit()
    
    # Broadcast to appropriate room
    room = str(group_id) if group_id else f"private_{min(current_user.id, recipient_id)}_{max(current_user.id, recipient_id)}"
    emit('new_message', {
        'message_id': message.id,
        'sender_id': current_user.id,
        'sender_name': current_user.username,
        'content': content,
        'timestamp': message.timestamp.isoformat(),
        'group_id': group_id
    }, room=room)

@socketio.on('typing')
def handle_typing(data):
    recipient_id = data.get('recipient_id')
    group_id = data.get('group_id')
    is_typing = data.get('is_typing', True)
    
    room = str(group_id) if group_id else f"private_{min(current_user.id, recipient_id)}_{max(current_user.id, recipient_id)}"
    emit('typing', {
        'user_id': current_user.id,
        'username': current_user.username,
        'is_typing': is_typing
    }, room=room)

# Call-related events
@socketio.on('call_request')
def handle_call_request(data):
    recipient_id = data.get('recipient_id')
    call_type = data.get('call_type', 'audio')
    
    emit('incoming_call', {
        'caller_id': current_user.id,
        'caller_name': current_user.username,
        'call_type': call_type
    }, room=f'user_{recipient_id}')
