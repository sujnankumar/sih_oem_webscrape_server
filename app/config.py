import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'Num3R1c@lly_Secure')

    TUTORIALS_FOLDER = os.path.join(os.getcwd(), 'tutorials')
    THUMBNAILS_FOLDER = os.path.join(os.getcwd(), 'tutorials/thumbnails')

    
    # Define the base directory for the app
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    
    # Define the directory for the database instance
    DB_DIR = os.path.join(BASE_DIR, 'instance')
    
    # Create the database directory if it doesn't exist
    os.makedirs(DB_DIR, exist_ok=True)  # Updated to use exist_ok=True for better readability
    
    # Configure the SQLAlchemy database URI
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL', 
        f'sqlite:///{os.path.join(DB_DIR, "db.sqlite3")}'
    )
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable track modifications to save memory

    # Optional: Define JWT secret key if using JWT
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'Str0ng_S3cr3t')

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'vulnerablity.tracker@gmail.com'
    MAIL_PASSWORD = 'zwzp wewn lkme uvif'
    MAIL_DEFAULT_SENDER = 'vulnerablity.tracker@gmail.com'
