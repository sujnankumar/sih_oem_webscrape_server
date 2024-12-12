from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_cors import CORS
import os
from queue import Queue


from flask_mail import Mail

mail = Mail()

# Initialize extensions
login_manager = LoginManager()
db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()
migrate = Migrate()
task_queue = Queue()

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config') 

    # CORS(app, origins="http://localhost:5173", supports_credentials=True)
    CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}},supports_credentials=True)

    
    # Initialize extensions with app
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    mail.init_app(app)

    # Register blueprints
    from .routes import register_blueprints
    register_blueprints(app)

    with app.app_context():
        # Import routes and models to register them
        from app import routes, models
        
        # Create the database tables if they don't exist
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        if not os.path.exists(db_path):
            db.create_all()

    return app
