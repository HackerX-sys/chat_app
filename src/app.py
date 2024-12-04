from flask import Flask
from flask_socketio import SocketIO
from flask_login import LoginManager
from src.core.models import db, User
from src.core.socket import socketio
from src.ui.routes import ui
from src.admin.routes import admin
import os

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    
    # Initialize extensions
    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")
    login_manager = LoginManager()
    login_manager.login_view = 'ui.login'
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Register blueprints
    app.register_blueprint(ui)
    app.register_blueprint(admin, url_prefix='/admin')
    
    # Create upload directory
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        # Create admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            from src.utils.security import create_user
            create_user('admin', 'admin123', is_admin=True)
    
    return app

def run_app():
    app = create_app()
    socketio.run(app, debug=True)

if __name__ == '__main__':
    run_app()
