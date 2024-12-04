from flask import Flask
import os
from src.core.extensions import db, socketio, login_manager
from src.core.models import User
from src.core.filters import timeago

def create_app():
    app = Flask(__name__, 
        template_folder='src/ui/templates',
        static_folder='src/static')

    # Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src/static/uploads')

    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    socketio.init_app(app, message_queue=None, cors_allowed_origins="*")
    login_manager.init_app(app)
    login_manager.login_view = 'ui.login'

    # Register filters
    app.jinja_env.filters['timeago'] = timeago

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register blueprints
    from src.ui.routes import ui
    app.register_blueprint(ui)

    # Initialize socket events
    from src.core.events import init_socket_events
    init_socket_events(socketio)

    # Initialize database
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            from werkzeug.security import generate_password_hash
            admin = User(
                username='admin',
                password_hash=generate_password_hash('admin'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()

    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
