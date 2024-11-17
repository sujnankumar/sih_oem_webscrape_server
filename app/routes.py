from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from . import db, login_manager
import bcrypt
from datetime import datetime
from flask_mail import Message
from . import mail

bp = Blueprint('auth', __name__)
api = Blueprint('api', __name__)

def register_blueprints(app):
    app.register_blueprint(bp, url_prefix='/auth')
    app.register_blueprint(api, url_prefix='/api')

def send_email_to_subscribers(subject, message_body):
    from .models import Subscriber  
    subscribers = Subscriber.query.all()
    print(list(subscribers))

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

@api.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    # Use get_jwt_identity to get the identity from the token
    identity = get_jwt_identity()
    return jsonify({'message': f'Welcome, {identity["username"]}!'})

@api.route('/insert_scraped_data', methods=['POST'])
def insert_scraped_data():
    from .models import Vulnerabilities  # Import the Vulnerabilities model inside the function
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

    # Create a new Vulnerabilities record
    new_entry = Vulnerabilities(
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

    db.session.add(new_entry)
    db.session.commit()

    return jsonify({'message': 'Data inserted successfully!'}), 201

# Route to retrieve OEM website scraped data (protected by JWT)
@api.route('/get_scraped_data', methods=['GET'])
@jwt_required()
def get_scraped_data():
    from .models import Vulnerabilities # Import the Vulnerabilities model inside the function

    # Retrieve all entries from the Vulnerabilities table
    scraped_data = Vulnerabilities.query.all()

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

@api.route('/search', methods=['POST'])
def search():
    from .models import Vulnerabilities

    product_name = request.form.get('product_name').lower()
    vulnerabilities = Vulnerabilities.query.filter(Vulnerabilities.product_name.ilike(f'%{product_name}%')).all()

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

@api.route('/suggestions', methods=['GET'])
def suggestions():
    from .models import Vulnerabilities
    search_term = request.args.get('term', '').lower()  # Get the term for suggestions

    # Check if the search term has at least 2 letters
    if len(search_term) < 2:
        return jsonify([])  # Return an empty list if the term is less than 2 characters

    products = Vulnerabilities.query.with_entities(Vulnerabilities.product_name).all()
    # Filter products that contain the search term (case-insensitive)
    filtered_products = [product[0] for product in products if search_term in product[0].lower()]
    return jsonify(filtered_products)

@api.route('/send_alerts', methods=['POST'])
def send_alerts():
    from .models import Alert, User, Vulnerabilities  # Import the necessary models inside the function

    data = request.get_json()
    vulnerability_id = data.get('vulnerability_id')

    if not vulnerability_id:
        return jsonify({'message': 'Missing vulnerability ID'}), 400

    # Retrieve the vulnerability details
    vulnerability = Vulnerabilities.query.get(vulnerability_id)
    if not vulnerability:
        return jsonify({'message': 'Vulnerability not found'}), 404

    # Retrieve all users
    users = User.query.all()

    for user in users:
        # Create an alert for each user
        new_alert = Alert(vulnerability_id=vulnerability_id, user_id=user.id)
        db.session.add(new_alert)
        db.session.commit()

        # Send email to the user
        subject = f"New Vulnerability Alert: {vulnerability.product_name}"
        message_body = f"""
        Dear {user.username},

        A new vulnerability has been identified:

        Product Name: {vulnerability.product_name}
        Version: {vulnerability.product_version}
        OEM: {vulnerability.oem_name}
        Severity Level: {vulnerability.severity_level}
        Vulnerability: {vulnerability.vulnerability}
        Mitigation Strategy: {vulnerability.mitigation_strategy}
        Published Date: {vulnerability.published_date.strftime('%B %Y')}

        Please take appropriate action!

        Best regards,
        Your Security Team
        """
        try:
            msg = Message(subject=subject, recipients=[user.email], body=message_body)
            mail.send(msg)
            new_alert.status = 'Sent'
        except Exception as e:
            new_alert.status = 'Failed'
            print(f"Failed to send email to {user.email}: {e}")

        db.session.commit()

    return jsonify({'message': 'Alerts processed successfully!'}), 200

@api.route('/add_website', methods=['POST'])
def add_website():
    from .models import OEMWebsite 

    data = request.get_json()
    oem_name = data.get('oem_name')
    website_url = data.get('website_url')

    if not oem_name or not website_url:
        return jsonify({'message': 'Missing required fields'}), 400

    # Check if the website already exists
    if OEMWebsite.query.filter_by(website_url=website_url).first():
        return jsonify({"error": "Website already exists"}), 400

    # Create a new OEMWebsite record
    new_website = OEMWebsite(oem_name=oem_name, website_url=website_url)
    db.session.add(new_website)
    db.session.commit()

    return jsonify({'message': 'Website added successfully!'}), 201


@api.route('/filter_and_sort_vulnerabilities', methods=['POST'])
@jwt_required()
def filter_and_sort_vulnerabilities():
    from .models import Vulnerabilities
    data = request.get_json()

    # Default values if no filters are provided
    severity = data.get('severity', None)
    oem_name = data.get('oem_name', None)
    product_name = data.get('product_name', None)
    sort_by = data.get('sort_by', 'published_date')  # Default sorting by published_date
    order = data.get('order', 'desc')  # Default sorting in descending order

    # Start with the base query
    query = Vulnerabilities.query

    # Apply filters if provided
    if severity:
        query = query.filter(Vulnerabilities.severity_level == float(severity)) 
    if oem_name:
        query = query.filter(Vulnerabilities.oem_name.ilike(f'%{oem_name}%'))
    if product_name:
        query = query.filter(Vulnerabilities.product_name.ilike(f'%{product_name}%'))

    # Apply sorting based on 'sort_by' and 'order'
    if sort_by in ['severity_level', 'published_date', 'scraped_date']:
        column = getattr(Vulnerabilities, sort_by)
        if order == 'asc':
            query = query.order_by(column.asc())
        else:
            query = query.order_by(column.desc())

    # Execute the query
    vulnerabilities = query.all()

    # Serialize the results
    results = [
        {
            'product_name': vuln.product_name,
            'product_version': vuln.product_version,
            'oem_name': vuln.oem_name,
            'severity_level': vuln.severity_level,
            'vulnerability': vuln.vulnerability,
            'mitigation_strategy': vuln.mitigation_strategy,
            'published_date': vuln.published_date.strftime('%Y-%m-%d'),
            'unique_id': vuln.unique_id,
            'scraped_date': vuln.scraped_date.strftime('%Y-%m-%d')
        }
        for vuln in vulnerabilities
    ]

    return jsonify(results), 200

