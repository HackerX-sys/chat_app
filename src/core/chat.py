from datetime import datetime
from src.core.models import db, Message, User

def send_message(sender_id, recipient_id, content, group_id=None):
    message = Message(
        content=content,
        sender_id=sender_id,
        recipient_id=recipient_id,
        group_id=group_id
    )
    db.session.add(message)
    db.session.commit()
    return message

def get_user_messages(user_id):
    return Message.query.filter(
        (Message.sender_id == user_id) | (Message.recipient_id == user_id)
    ).order_by(Message.timestamp.desc()).all()

def get_conversation(user1_id, user2_id):
    return Message.query.filter(
        ((Message.sender_id == user1_id) & (Message.recipient_id == user2_id)) |
        ((Message.sender_id == user2_id) & (Message.recipient_id == user1_id))
    ).order_by(Message.timestamp.asc()).all()
