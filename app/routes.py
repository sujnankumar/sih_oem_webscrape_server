from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from . import db, login_manager
import bcrypt
from datetime import datetime
from flask_mail import Message
from . import mail

bp = Blueprint('auth', __name__)

def register_blueprints(app):
    app.register_blueprint(bp, url_prefix='/auth')

def send_email_to_subscribers(subject, message_body):
    from .models import Subscriber  
    subscribers = Subscriber.query.all()
    print(subscribers)

    with mail.connect() as conn:
        for subscriber in subscribers:
            msg = Message(
                subject=subject,
                recipients=[subscriber.email],
                body=message_body
            )
            conn.send(msg)

@login_manager.user_loader
def load_user(user_id):
    from .models import User  # Avoid circular import by importing inside the function
    return User.query.get(int(user_id))

@bp.route('/register', methods=['POST'])
def register():
    from .models import User  # Import User inside the function

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'Missing fields'}), 400

    # Check if email or username already exists
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken"}), 400

    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Create and save new user
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Registration successful!'}), 201

@bp.route('/login', methods=['POST'])
def login():
    from .models import User  # Import User inside the function

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Missing required fields"}), 400

    user = User.query.filter_by(email=email).first()
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        # Create a JWT token
        access_token = create_access_token(identity={'id': user.id, 'username': user.username, 'email': user.email})
        return jsonify({
            'message': 'Login successful!',
            'access_token': access_token,
            'user': {
                'username': user.username,
                'email': user.email
            }
        }), 200

    return jsonify({'message': 'Invalid email or password'}), 401

@bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # For JWT, logout can be handled on the client-side by discarding the token
    return jsonify({'message': 'Successfully logged out'}), 200

@bp.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    # Use get_jwt_identity to get the identity from the token
    identity = get_jwt_identity()
    return jsonify({'message': f'Welcome, {identity["username"]}!'})

@bp.route('/insert_scraped_data', methods=['POST'])
def insert_scraped_data():
    from .models import OEMData  # Import the OEMData model inside the function
    data = request.get_json()

    # Extract the required fields
    product_name = data.get('product_name')
    product_version = data.get('product_version', 'NA')
    oem_name = data.get('oem_name')
    severity_level = data.get('severity_level')
    vulnerability = data.get('vulnerability')
    mitigation_strategy = data.get('mitigation_strategy')
    published_date = datetime.strptime(data.get('published_date'), '%B %Y').date()
    unique_id = data.get('unique_id')
    scraped_date = datetime.now().date()

    if not all([product_name, oem_name, severity_level, vulnerability, mitigation_strategy, unique_id]):
        return jsonify({'message': 'Missing required fields'}), 400

    # Create a new OEMData record
    new_entry = OEMData(
        product_name=product_name,
        product_version=product_version,
        oem_name=oem_name,
        severity_level=severity_level,
        vulnerability=vulnerability,
        mitigation_strategy=mitigation_strategy,
        published_date=published_date,
        unique_id=unique_id,
        scraped_date=scraped_date
    )

    # db.session.add(new_entry)
    # db.session.commit()



    # Send email notifications to subscribers
    subject = f"New Vulnerability Found for {product_name}"
    message_body = f"""
    A new vulnerability has been scraped:
    
    Product Name: {product_name}
    Version: {product_version}
    OEM: {oem_name}
    Severity Level: {severity_level}
    Vulnerability: {vulnerability}
    Mitigation Strategy: {mitigation_strategy}
    Published Date: {published_date.strftime('%B %Y')}
    
    Please take appropriate action!
    """
    send_email_to_subscribers(subject, message_body)



    return jsonify({'message': 'Data inserted successfully!'}), 201

# Route to retrieve OEM website scraped data (protected by JWT)
@bp.route('/get_scraped_data', methods=['GET'])
@jwt_required()
def get_scraped_data():
    from .models import OEMData  # Import the OEMData model inside the function

    # Retrieve all entries from the OEMData table
    scraped_data = OEMData.query.all()

    # Serialize the data to JSON
    data_list = [
        {
            'product_name': data.product_name,
            'product_version': data.product_version,
            'oem_name': data.oem_name,
            'severity_level': data.severity_level,
            'vulnerability': data.vulnerability,
            'mitigation_strategy': data.mitigation_strategy,
            'published_date': data.published_date,
            'unique_id': data.unique_id,
            'scraped_date': data.scraped_date
        }
        for data in scraped_data
    ]

    return jsonify({'data': data_list}), 200

@bp.route('/search', methods=['POST'])
def search():
    from .models import OEMData

    product_name = request.form.get('product_name').lower()
    vulnerabilities = OEMData.query.filter(OEMData.product_name.ilike(f'%{product_name}%')).all()

    results = [
        {
            "product_name": vuln.product_name,
            "product_version": vuln.product_version,
            "oem_name": vuln.oem_name,
            "severity_level": vuln.severity_level,
            "vulnerability": vuln.vulnerability,
            "mitigation_strategy": vuln.mitigation_strategy,
            "published_date": vuln.published_date,
            "unique_id": vuln.unique_id
        }
        for vuln in vulnerabilities
    ]
    return jsonify(results)

@bp.route('/suggestions', methods=['GET'])
def suggestions():
    from .models import OEMData
    search_term = request.args.get('term', '').lower()  # Get the term for suggestions

    # Check if the search term has at least 2 letters
    if len(search_term) < 2:
        return jsonify([])  # Return an empty list if the term is less than 2 characters

    products = OEMData.query.with_entities(OEMData.product_name).all()
    # Filter products that contain the search term (case-insensitive)
    filtered_products = [product[0] for product in products if search_term in product[0].lower()]
    return jsonify(filtered_products)