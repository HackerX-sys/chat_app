from werkzeug.security import generate_password_hash, check_password_hash
from ..core.models import User, db

def create_user(username, password, is_admin=False):
    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        is_admin=is_admin
    )
    db.session.add(user)
    db.session.commit()
    return user

def verify_password(user, password):
    return check_password_hash(user.password_hash, password)

def change_password(user, new_password):
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
