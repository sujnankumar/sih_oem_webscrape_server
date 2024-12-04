from flask import Blueprint, jsonify, request, make_response, send_from_directory
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
    otp = data.get('otp')

    if not email or not password:
        return jsonify({"error": "Missing required fields"}), 400
    
    stored_otp = User.query.filter_by(email=email).first().otp
    stored_otp_generated_at = User.query.filter_by(email=email).first().otp_generated_at

    if not stored_otp or not stored_otp_generated_at:
        return jsonify({"error": "OTP not generated"}), 400
    
    if (datetime.now() - stored_otp_generated_at).seconds > 600:
        return jsonify({"error": "OTP expired"}), 401

    if stored_otp != otp:
        return jsonify({"error": "Invalid OTP"}), 401

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

@bp.route('/get_otp', methods=['POST'])
def get_otp():
    from .models import User  # Import User inside the function
    import random

    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Missing email field"}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"error": "Email not found"}), 404

    # Generate a random 6-digit OTP
    otp = random.randint(100000, 999999)

    # Save the OTP to the user's record (assuming there's a field for it)
    user.otp = otp
    user.otp_generated_at = datetime.now()
    db.session.commit()

    subject = "Your OTP Code for Login on Vulnerability Tracker"
    message_body = f"\nYour OTP code is {otp}.\n It is valid for 10 minutes.\nDo not share this with anyone!"
    msg = Message(subject=subject, recipients=[email], body=message_body)
    mail.send(msg)

    return jsonify({"message": "OTP sent successfully"}), 200

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


@api.route('/home/vulnerabilities', methods=['GET'])
def get_vulnerabilities_per_month():
    """
    Fetch the number of vulnerabilities discovered per month.
    Returns data formatted for a chart: months and counts.
    """
    from sqlalchemy import extract, func
    from .models import Vulnerabilities

    # Query to group by month and year and count vulnerabilities
    vulnerabilities_per_month = (
        db.session.query(
            func.strftime('%Y-%m', Vulnerabilities.scraped_date).label('month_year'),
            func.count(Vulnerabilities.id).label('count')
        )
        .group_by(func.strftime('%Y-%m', Vulnerabilities.scraped_date))
        .order_by(func.strftime('%Y-%m', Vulnerabilities.scraped_date))
        .all()
    )

    # Format response data
    response = [
        {"month": row[0], "count": row[1]} for row in vulnerabilities_per_month
    ]

    return jsonify(response)



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
# @jwt_required()
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
def report_vulnerability():
    """
    Allows users to report a vulnerability they found.
    """
    from .models import ReportedVulnerability

    # Get the data from the request body
    data = request.get_json()

    # Validate input data
    if not all(key in data for key in ['product_name', 'oem_name', 'vulnerability_description', 'severity_level']):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        # Create a new reported vulnerability entry
        new_report = ReportedVulnerability(
            user_id=current_user.id,
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
        return jsonify({"error": f"An error occurred while submitting the report: {str(e)}"}), 500
    

@api.route('/reported-vulnerabilities', methods=['GET'])
def get_reported_vulnerabilities():
    """
    Allows users to retrieve the reported vulnerabilities they have submitted.
    """
    from .models import ReportedVulnerability

    try:
        # Fetch all reported vulnerabilities by the logged-in user
        reported_vulnerabilities = ReportedVulnerability.query.filter_by(user_id=current_user.id).all()
        # reported_vulnerabilities = ReportedVulnerability.query.filter_by(user_id=1).all()

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
