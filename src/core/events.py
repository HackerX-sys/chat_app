from flask import current_app
from flask_socketio import emit, join_room, leave_room
from flask_login import current_user
from datetime import datetime
from .models import Message, User, Notification
from .extensions import db, socketio

def init_socket_events(_socketio=None):
    # Use the imported socketio if no instance is provided
    socket = _socketio or socketio

    @socket.on('connect')
    def handle_connect():
        if current_user.is_authenticated:
            join_room(f'user_{current_user.id}')
            current_user.online = True
            db.session.commit()
            emit('status_change', 
                 {'user_id': current_user.id, 'status': 'online'}, 
                 broadcast=True)

    @socket.on('disconnect')
    def handle_disconnect():
        if current_user.is_authenticated:
            leave_room(f'user_{current_user.id}')
            current_user.online = False
            current_user.last_seen = datetime.utcnow()
            db.session.commit()
            emit('status_change', 
                 {'user_id': current_user.id, 'status': 'offline'}, 
                 broadcast=True)

    @socket.on('message')
    def handle_message(data):
        if current_user.is_authenticated:
            message = Message(
                content=data['content'],
                sender_id=current_user.id,
                recipient_id=data.get('recipient_id'),
                group_id=data.get('group_id'),
                message_type=data.get('message_type', 'text'),
                file_url=data.get('file_url'),
                file_type=data.get('file_type')
            )
            db.session.add(message)
            db.session.commit()

            message_data = {
                'id': message.id,
                'content': message.content,
                'sender_id': message.sender_id,
                'sender_name': current_user.username,
                'timestamp': message.timestamp.isoformat(),
                'message_type': message.message_type,
                'file_url': message.file_url,
                'file_type': message.file_type
            }

            # Emit to recipient's room if direct message
            if message.recipient_id:
                emit('new_message', message_data, room=f'user_{message.recipient_id}')
                
                # Create notification for offline user
                recipient = User.query.get(message.recipient_id)
                if not recipient.online:
                    notification = Notification(
                        user_id=message.recipient_id,
                        type='message',
                        content=f'New message from {current_user.username}',
                        related_id=message.id
                    )
                    db.session.add(notification)
                    db.session.commit()

            # Emit to group room if group message
            elif message.group_id:
                emit('new_message', message_data, room=f'group_{message.group_id}')

            # Always emit back to sender
            emit('new_message', message_data, room=f'user_{current_user.id}')

    @socket.on('typing')
    def handle_typing(data):
        if current_user.is_authenticated:
            room = None
            if 'recipient_id' in data:
                room = f'user_{data["recipient_id"]}'
            elif 'group_id' in data:
                room = f'group_{data["group_id"]}'
            
            if room:
                emit('typing', {
                    'user_id': current_user.id,
                    'username': current_user.username,
                    'is_typing': data['is_typing']
                }, room=room)

    @socket.on('join_group')
    def handle_join_group(data):
        if current_user.is_authenticated:
            group_id = data.get('group_id')
            if group_id:
                join_room(f'group_{group_id}')
                emit('user_joined_group', {
                    'user_id': current_user.id,
                    'username': current_user.username,
                    'group_id': group_id
                }, room=f'group_{group_id}')
