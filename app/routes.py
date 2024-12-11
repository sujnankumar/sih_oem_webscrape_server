from flask import Blueprint, jsonify, request, make_response, send_from_directory, session
from flask_login import login_required, current_user
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from . import db, login_manager
import bcrypt
from datetime import datetime
from flask_mail import Message
from . import mail
import csv
import json
from io import StringIO, BytesIO
from fpdf import FPDF
import os
from .config import Config

import random

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


@bp.route('/get_otp', methods=['POST'])
def get_otp():
    """
    Generate and store a new OTP for the given email.
    """
    import random

    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Missing email field"}), 400

    # Check if email is already registered in User table
    from .models import User
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 400
    
    from .models import OTP

    # Generate a random 6-digit OTP
    otp = random.randint(100000, 999999)

    # Save the new OTP record
    new_otp = OTP(email=email, otp=str(otp))
    db.session.add(new_otp)
    db.session.commit()

    # Send OTP to user's email
    subject = "Your OTP Code for Registration"
    message_body = f"\nYour OTP code is {otp}.\n It is valid for 10 minutes.\nDo not share this with anyone!"
    msg = Message(subject=subject, recipients=[email], body=message_body)
    mail.send(msg)

    return jsonify({"message": "OTP sent successfully"}), 200


@bp.route('/verify_otp', methods=['POST'])
def verify_otp():
    """
    Verify the latest OTP for the given email.
    """
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({"error": "Missing email or OTP"}), 400
    
    from .models import OTP

    # Fetch the latest OTP for the given email
    latest_otp_record = OTP.query.filter_by(email=email).order_by(OTP.created_at.desc()).first()

    if not latest_otp_record:
        print("error OTP not generated for this email")
        return jsonify({"error": "OTP not generated for this email"}), 404

    # Check if the entered OTP matches the latest one
    if latest_otp_record.otp != otp:
        # Check if the entered OTP is older
        older_otp_record = OTP.query.filter_by(email=email, otp=otp).first()
        if older_otp_record:
            print({"error": "This is an old OTP. Please use the latest OTP sent to your email."})
            return jsonify({"error": "This is an old OTP. Please use the latest OTP sent to your email."}), 403
        print({"error": "Invalid OTP"})
        return jsonify({"error": "Invalid OTP"}), 401

    # Check if the latest OTP is expired
    if (datetime.utcnow() - latest_otp_record.created_at).seconds > 600:
        print("otp expired")
        return jsonify({"error": "The OTP has expired. Please request a new one."}), 403

    # OTP is valid and not expired, proceed with email verification
    
    return jsonify({"message": "OTP verified successfully"}), 200



@bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user after verifying the OTP.
    """
    from .models import User

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'Missing fields'}), 400

    # Check if email is verified in the database
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({"error": "User with this email already exists"}), 404


    # Check if username is already taken
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken"}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Create and save new user
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Registration successful!'}), 201


@bp.route('/login', methods=['POST'])
def login():
    """
    Login a user with email and password.
    """
    from .models import User

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400

    # Fetch the user
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({'error': 'Invalid email or password'}), 401

    # Create access token
    access_token = create_access_token(identity={'id': user.id, 'username': user.username, 'email': user.email})
    return jsonify({
        'message': 'Login successful!',
        'access_token': access_token,
        'user': {
            'username': user.username,
            'email': user.email
        }
    }), 200

@bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify({'message': 'Successfully logged out'}), 200
    

@api.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    # Use get_jwt_identity to get the identity from the token
    identity = get_jwt_identity()
    return jsonify({'message': f'Welcome, {identity["username"]}!'})


@api.route('/admin/add-website', methods=['POST'])
@jwt_required()
def add_website():
    """
    API to allow admin to add a new website.
    """
    from .models import OEMWebsite

    # Extract data from the request
    data = request.get_json()

    is_admin = get_jwt_identity()['is_admin']

    if not is_admin:
        return jsonify({"error": "Unauthorized access. You are not recognised as admin."}), 403

    # Validate the input data
    required_fields = ['website', 'oem_name', 'scrape_frequency', 'options']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        # Unpack form data
        website_name = data['website']
        oem_name = data['oem_name']
        scrape_frequency = int(data['scrape_frequency'])
        options = data['options']

        # Add new website entry to the database
        new_website = OEMWebsite(
            website_url=website_name,
            oem_name=oem_name,
            scrape_frequency=scrape_frequency,
            contains_listing=options.get('contains_listing', False),
            contains_details=options.get('contains_details', False),
            contains_date=options.get('contains_date', False),
            is_it=options.get('is_it', False),
            is_official=options.get('is_official', False),
        )

        # Commit the new website to the database
        db.session.add(new_website)
        db.session.commit()

        return jsonify({"message": "Website added successfully!"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error adding website: {str(e)}")
        return jsonify({"error": "An error occurred while adding the website."}), 500



@api.route('/home/vulnerabilities/number_breakdown', methods=['GET'])
def get_vulnerabilities_summary():
    """
    Fetch the total number of vulnerabilities and counts grouped by severity.
    Returns total count and severity-wise breakdown.
    """
    from sqlalchemy import func
    from .models import Vulnerabilities

    
    total_count = db.session.query(func.count(Vulnerabilities.id)).scalar()

    
    severity_counts = (
        db.session.query(
            Vulnerabilities.severity_level.label('severity'),
            func.count(Vulnerabilities.id).label('count')
        )
        .group_by(Vulnerabilities.severity_level)
        .all()
    )

    
    severity_data = [{"severity": row[0], "count": row[1]} for row in severity_counts]

    response = {
        "total_vulnerabilities": total_count,
        "severity_breakdown": severity_data
    }

    return jsonify(response)


@api.route('/home/vulnerabilities/recent', methods=['GET'])
def get_recent_vulnerabilities():
    """
    Fetch the most recently added vulnerabilities.
    Returns the vulnerability, severity level, and date.
    """
    from .models import Vulnerabilities

    # Query to get recently added vulnerabilities, ordered by date (descending)
    recent_vulnerabilities = (
        db.session.query(
            Vulnerabilities.vulnerability.label('vulnerability'),
            Vulnerabilities.severity_level.label('severity'),
            Vulnerabilities.scraped_date.label('date')
        )
        .order_by(Vulnerabilities.scraped_date.desc())
        .limit(8)  # Limit to the last 10 vulnerabilities; adjust as needed
        .all()
    )

    # Format response data
    response = [
        {
            "vulnerability": row[0],
            "severity_level": row[1],
            "date": row[2].strftime('%Y-%m-%d %H:%M:%S') if row[2] else None
        }
        for row in recent_vulnerabilities
    ]

    return jsonify(response)


@api.route('/home/vulnerabilities_per_month', methods=['GET'])
def get_vulnerabilities_per_month():
    """
    Fetch the number of vulnerabilities discovered per month grouped by severity.
    Returns data formatted for a chart: months, severities, and counts.
    """
    from sqlalchemy import extract, func
    from .models import Vulnerabilities

    # Query to group by year, month, and severity and count vulnerabilities
    vulnerabilities_per_month = (
        db.session.query(
            func.strftime('%Y-%m', Vulnerabilities.scraped_date).label('month_year'),
            Vulnerabilities.severity_level.label('severity'),
            func.count(Vulnerabilities.id).label('count')
        )
        .group_by(
            func.strftime('%Y-%m', Vulnerabilities.scraped_date),
            Vulnerabilities.severity_level
        )
        .order_by(func.strftime('%Y-%m', Vulnerabilities.scraped_date))
        .all()
    )

    # Organize response data
    monthly_data = {}
    for row in vulnerabilities_per_month:
        month = row[0]
        severity = row[1]
        count = row[2]

        # Initialize month entry if not present
        if month not in monthly_data:
            monthly_data[month] = {"month": month, "details": []}

        # Add severity and count details
        monthly_data[month]["details"].append({"severity": severity, "count": count})

    # Convert monthly_data to a list of values for JSON response
    response = list(monthly_data.values())

    return jsonify(response)


@api.route('/admin/scraping-log', methods=['POST'])
def log_scraping_status():
    """
    Log the status of a scraping attempt (success or error).
    Links the log to an OEMWebsite via the website_id.
    """
    from .models import ScrapingLogs, OEMWebsite

    # Extract data from the request body
    website_url = request.json.get('website_url')
    status = request.json.get('status')  # Should be either 'success' or 'error'
    error_message = request.json.get('error', None)

    # Find the OEMWebsite object using the website_url
    website = OEMWebsite.query.filter_by(website_url=website_url).first()

    if website:
        # Create a new ScrapingLogs entry with the correct website_id
        log_entry = ScrapingLogs(
            website_url=website_url,
            status=status,
            error_message=error_message,
            website_id=website.id  # Reference to OEMWebsite
        )

        # Add the log entry to the database
        db.session.add(log_entry)
        db.session.commit()

        return jsonify({"message": "Scraping status logged successfully"}), 201
    else:
        return jsonify({"message": "Website not found"}), 404


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
def get_scraped_data_summary():
    """
    Retrieve a summary of vulnerability data with selected fields.
    """
    from .models import Vulnerabilities  # Import the Vulnerabilities model inside the function

    # Retrieve all entries from the Vulnerabilities table
    scraped_data = Vulnerabilities.query.all()

    # Serialize the data to JSON with specified fields
    data_list = [
        {
            'product_name_version': data.product_name_version,
            'vendor': data.vendor,
            'severity_level': data.severity_level,
            'vulnerability': data.vulnerability,
            'published_date': data.published_date.strftime('%Y-%m-%d') if data.published_date else None,
            'reference': data.reference
        }
        for data in scraped_data
    ]

    return jsonify({'data': data_list}), 200


@api.route('/search', methods=['POST'])
def search():
    """
    Search vulnerabilities across multiple fields.
    """
    from .models import Vulnerabilities

    # Get the search term from the request
    search_term = request.form.get('search_term', '').lower()

    if not search_term:
        return jsonify({"error": "Search term is required"}), 400

    # Query the database for entries matching the search term in any relevant field
    vulnerabilities = Vulnerabilities.query.filter(
        db.or_(
            Vulnerabilities.product_name_version.ilike(f'%{search_term}%'),
            Vulnerabilities.vendor.ilike(f'%{search_term}%'),
            Vulnerabilities.severity_level.ilike(f'%{search_term}%'),
            Vulnerabilities.vulnerability.ilike(f'%{search_term}%'),
            Vulnerabilities.reference.ilike(f'%{search_term}%')
        )
    ).all()

    # Serialize the results
    results = [
        {
            "product_name_version": vuln.product_name_version,
            "vendor": vuln.vendor,
            "severity_level": vuln.severity_level,
            "vulnerability": vuln.vulnerability,
            "published_date": vuln.published_date.strftime('%Y-%m-%d') if vuln.published_date else None,
            "reference": vuln.reference
        }
        for vuln in vulnerabilities
    ]

    return jsonify(results)



@api.route('/get_it_ot_number', methods=['GET'])
def it_ot_number():
    from .models import OEMWebsite
    try:

        # Get counts of IT and OT websites
        it_count = OEMWebsite.query.filter_by(is_it=True).count()
        ot_count = OEMWebsite.query.filter_by(is_it=False).count()
        # If both counts are 0, return a 404 error
        if it_count == 0 and ot_count == 0:
            return jsonify({"message": "No data found"}), 404

        # Return counts as JSON response
        return jsonify({"it_count": it_count, "ot_count": ot_count}), 200

    except Exception as e:
        # Handle unexpected errors, e.g., database connection issues
        return jsonify({"error": str(e)}), 500


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

@api.route('/user/alerts', methods=['GET'])
def get_user_alerts():
    """
    Retrieve all alerts (mails) sent to the current user.
    """
    from .models import Alert

    try:
        # Retrieve all alerts for the logged-in user
        alerts = Alert.query.filter_by(user_id=current_user.id).all()
        # alerts = Alert.query.filter_by(user_id=1).all()

        if not alerts:
            return jsonify({"message": "No alerts found for this user."}), 404

        # Prepare the response data
        alerts_data = []
        for alert in alerts:
            alert_data = {
                "vulnerability_id": alert.vulnerability_id,
                "vulnerability_name": alert.vulnerability.product_name,
                "oem_name": alert.vulnerability.oem_name,
                "severity_level": alert.vulnerability.severity_level,
                "status": alert.status,
                "email_sent_timestamp": alert.email_sent_timestamp.strftime('%Y-%m-%d %H:%M:%S') if alert.email_sent_timestamp else None,
                "vulnerability_details": alert.vulnerability.vulnerability
            }
            alerts_data.append(alert_data)

        return jsonify({"alerts": alerts_data}), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred while retrieving alerts: {str(e)}"}), 500


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

@api.route('/start_scraping', methods=['POST'])
def start_scraping():
    from .scrape.scraper import scrape_oem_websites

    try:
        scrape_oem_websites()
        return jsonify({'message': 'Scraping started successfully!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/start_scraping/custom', methods=['POST'])
def start_custom_scraping():
    from .scrape.scraper import scrape_oem_websites_custom
    # get data from the frontend as list of websites and perform scraping on only that 
    data = request.get_json()
    websites = data.get('websites', [])

    if not websites:
        return jsonify({'error': 'No websites provided'}), 400
    
    try:
        scrape_oem_websites_custom(websites)
        return jsonify({'message': 'Custom scraping started successfully!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@api.route('/start_scraping/filter', methods=['POST'])
def start_filtered_scrape():
    from .scrape.scraper import scrape_oem_websites_with_filter

    data = request.get_json()
    filters = data.get('filters', {})

    if not filters:
        return jsonify({'error': 'No filters provided'}), 400
    
    try:
        scrape_oem_websites_with_filter(filters)
        return jsonify({'message': 'Filtered scraping started successfully!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@api.route('/export', methods=['GET'])
def export_data():
    from .models import Vulnerabilities  
    export_format = request.args.get('format', 'json').lower() 
    data = Vulnerabilities.query.all()

    if not data:
        return jsonify({'error': 'No data found' }), 500

    # Serialize data
    serialized_data = [
        {
            "product_name": item.product_name,
            "product_version": item.product_version,
            "oem_name": item.oem_name,
            "severity_level": item.severity_level,
            "vulnerability": item.vulnerability,
            "mitigation_strategy": item.mitigation_strategy,
            "published_date": item.published_date.strftime('%Y-%m-%d'),
            "unique_id": item.unique_id,
            "scraped_date": item.scraped_date.strftime('%Y-%m-%d')
        }
        for item in data
    ]

    if export_format == 'csv':
        # Generate CSV
        si = StringIO()
        writer = csv.DictWriter(si, fieldnames=serialized_data[0].keys())
        writer.writeheader()
        writer.writerows(serialized_data)
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=data.csv"
        output.headers["Content-type"] = "text/csv"
        return output

    elif export_format == 'pdf':
        # Generate PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        for item in serialized_data:
            for key, value in item.items():
                pdf.cell(0, 10, f"{key}: {value}", ln=True)
            pdf.cell(0, 10, "", ln=True)  # Add space between entries

        # Write PDF to BytesIO
        output = BytesIO()
        pdf_output = pdf.output(dest='S').encode('latin1')  # Output PDF as string and encode
        output.write(pdf_output)
        output.seek(0)

        # Create Flask response
        response = make_response(output.read())
        response.headers["Content-Disposition"] = "attachment; filename=data.pdf"
        response.headers["Content-type"] = "application/pdf"
        return response


    # Default to JSON
    response = make_response(json.dumps(serialized_data))
    response.headers["Content-Disposition"] = "attachment; filename=data.json"
    response.headers["Content-type"] = "application/json"
    return response


@api.route('/tutorials', methods=['GET'])
def list_videos():
    """List all tutorial videos"""
    # videos = [
    #     {"name": f, "url": f"/api/tutorials/{f}"}
    #     for f in os.listdir(Config.TUTORIALS_FOLDER) if f.endswith(('.mp4', '.webm', '.ogg'))
    # ]

    videos = [
        {
            "name": f,
            "url": f"http://localhost:5000/api/tutorials/{f}",
            "thumbnail": f"http://localhost:5000/api/tutorials/thumbnails/{f.split('.')[0]}.jpg"
        }
        for f in os.listdir(Config.TUTORIALS_FOLDER) if f.endswith(('.mp4', '.webm', '.ogg'))
    ]

    return jsonify(videos)

@api.route('/tutorials/<filename>', methods=['GET'])
def get_video(filename):
    """Serve a specific tutorial video"""
    return send_from_directory(Config.TUTORIALS_FOLDER, filename)

@api.route('/tutorials/thumbnails/<filename>', methods=['GET'])
def get_thumb(filename):
    """Serve a specific tutorial video"""
    return send_from_directory(Config.THUMBNAILS_FOLDER, filename)


@api.route('/threads', methods=['GET'])
def get_threads():
    """Fetch all discussion threads."""
    from .models import Thread
    threads = Thread.query.all()
    result = [
        {
            "id": thread.id,
            "title": thread.title,
            "created_at": thread.created_at,
            "user": thread.user.username,
            "comments_count": len(thread.comments)
        }
        for thread in threads
    ]
    return jsonify(result)


@api.route('/threads', methods=['POST'])
def create_thread():
    """Create a new discussion thread."""
    from .models import Thread
    data = request.json
    title = data.get("title")

    if not title:
        return jsonify({"error": "Title is required"}), 400

    thread = Thread(title=title, user_id=current_user.id)
    db.session.add(thread)
    db.session.commit()
    return jsonify({"message": "Thread created successfully", "thread_id": thread.id}), 201


@api.route('/threads/<int:thread_id>/comments', methods=['POST'])
def add_comment(thread_id):
    """Add a comment to a thread."""
    from .models import Comment
    data = request.json
    text = data.get("text")

    if not text:
        return jsonify({"error": "Comment text is required"}), 400

    comment = Comment(text=text, thread_id=thread_id, user_id=current_user.id)
    db.session.add(comment)
    db.session.commit()
    return jsonify({"message": "Comment added successfully", "comment_id": comment.id}), 201


@api.route('/comments/<int:comment_id>/vote', methods=['PATCH'])
def vote_comment(comment_id):
    """Upvote or downvote a comment."""
    from .models import Comment
    data = request.json
    action = data.get("action")

    comment = Comment.query.get(comment_id)
    if not comment:
        return jsonify({"error": "Comment not found"}), 404

    if action == "upvote":
        comment.upvotes += 1
    elif action == "downvote":
        comment.downvotes += 1
    else:
        return jsonify({"error": "Invalid action"}), 400

    db.session.commit()
    return jsonify({"message": "Vote updated", "upvotes": comment.upvotes, "downvotes": comment.downvotes}), 200

@api.route('/report-vulnerability', methods=['POST'])
@jwt_required()
def report_vulnerability():
    """
    Allows users to report a vulnerability they found.
    """
    from .models import ReportedVulnerability
    # Get the data from the request body
    data = request.get_json()
    user = get_jwt_identity()
    user_id = user['id']

    # Validate input data
    if not all(key in data for key in ['product_name', 'oem_name', 'vulnerability_description', 'severity_level']):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        # Create a new reported vulnerability entry
        new_report = ReportedVulnerability(
            user_id=user_id,
            product_name=data['product_name'],
            oem_name=data['oem_name'],
            vulnerability_description=data['vulnerability_description'],
            severity_level=data['severity_level'],
            suggested_mitigation=data.get('suggested_mitigation')  # Optional field
        )

        # Add the new report to the database
        db.session.add(new_report)
        db.session.commit()

        return jsonify({"message": "Vulnerability report submitted successfully!"}), 201
    except Exception as e:
        db.session.rollback()
        print(e)
        return jsonify({"error": f"An error occurred while submitting the report: {str(e)}"}), 500
    

@api.route('/reported-vulnerabilities', methods=['GET'])
@jwt_required()
def get_reported_vulnerabilities():
    """
    Allows users to retrieve the reported vulnerabilities they have submitted.
    """
    from .models import ReportedVulnerability

    user = get_jwt_identity()
    print(user)
    user_id = user['id']

    try:
        
        # Fetch all reported vulnerabilities by the logged-in user
        reported_vulnerabilities = ReportedVulnerability.query.filter_by(user_id=user_id).all()
        # reported_vulnerabilities = ReportedVulnerability.query.filter_by(user_id=1).all()
        print(reported_vulnerabilities)
        # Format the response
        vulnerabilities_list = [
            {
                "id": v.id,
                "product_name": v.product_name,
                "oem_name": v.oem_name,
                "vulnerability_description": v.vulnerability_description,
                "severity_level": v.severity_level,
                "suggested_mitigation": v.suggested_mitigation,
                "status": v.status,
                "reported_date": v.reported_date.strftime('%Y-%m-%d %H:%M:%S')
            }
            for v in reported_vulnerabilities
        ]
        
        return jsonify(vulnerabilities_list), 200
    except Exception as e:
        return jsonify({"error": f"An error occurred while retrieving the reported vulnerabilities: {str(e)}"}), 500


@api.route('/admin/action-on-report/<int:report_id>', methods=['PATCH'])
def take_action_on_report(report_id):
    """
    Allows the admin to take action on a reported vulnerability.
    """
    from .models import ReportedVulnerability
    
    try:
        # Retrieve the reported vulnerability by ID
        reported_vulnerability = ReportedVulnerability.query.get_or_404(report_id)

        # Get the new status from the request
        new_status = request.json.get('status')

        # Validate status
        if new_status not in ['Reviewed', 'Accepted', 'Rejected']:
            return jsonify({"error": "Invalid status. Allowed values are 'Reviewed', 'Accepted', 'Rejected'."}), 400
        
        # Update the status of the report
        reported_vulnerability.status = new_status

        # Commit the change to the database
        db.session.commit()

        return jsonify({"message": f"Report {report_id} updated to {new_status}."}), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred while taking action on the report: {str(e)}"}), 500

@api.route('api/admin/dashboard', methods=['GET'])
@jwt_required()
def admin_dashboard():
    from .models import OEMWebsite, ScrapingLogs
    #get the website name, last_scraped and status
    try:
        results = db.session.query(
            OEMWebsite.oem_name,
            OEMWebsite.last_scraped,
            ScrapingLogs.status
        ).join(ScrapingLogs, OEMWebsite.id == ScrapingLogs.website_id).all()
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    # Build the list with the combined data
    website_list = [
        {"website_name": oem_name, "last_scraped": last_scraped, "status": status}
        for oem_name, last_scraped, status in results
    ]

    return jsonify(website_list),200
        



    