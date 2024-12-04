from app import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    otp = db.Column(db.String(6), nullable=True)
    otp_generated_at = db.Column(db.DateTime, nullable=True)
    
    # Fields for user interest areas
    interested_in_critical = db.Column(db.Boolean, default=True, nullable=False)
    interested_in_high = db.Column(db.Boolean, default=True, nullable=False)
    interested_in_product_categories = db.Column(db.Text)  # Stores product categories of interest, like 'Networking, OS'

    def __init__(self, username, email, password, interested_in_critical=True, interested_in_high=True, interested_in_product_categories=''):
        self.username = username
        self.email = email
        self.password = password
        self.interested_in_critical = interested_in_critical
        self.interested_in_high = interested_in_high
        self.interested_in_product_categories = interested_in_product_categories

    def get_id(self):
        """Override `get_id` to return a string (required by Flask-Login)."""
        return str(self.id)


class OEMWebsite(db.Model):
    __tablename__ = 'oem_websites'

    id = db.Column(db.Integer, primary_key=True)
    oem_name = db.Column(db.String(150), nullable=False)
    website_url = db.Column(db.Text, nullable=False)
    last_scraped = db.Column(db.DateTime, nullable=True)

    def __init__(self, oem_name, website_url, last_scraped=None):
        self.oem_name = oem_name
        self.website_url = website_url
        self.last_scraped = last_scraped


class Vulnerabilities(db.Model):
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(150), nullable=False)
    product_version = db.Column(db.String(100), nullable=True)
    oem_name = db.Column(db.String(150), nullable=False)
    severity_level = db.Column(db.Float, nullable=False)  # Critical or High 0-10
    vulnerability = db.Column(db.Text, nullable=False)
    mitigation_strategy = db.Column(db.Text, nullable=False)
    published_date = db.Column(db.Date, nullable=False)
    unique_id = db.Column(db.String(50), unique=True, nullable=False)  # CVE ID or similar
    scraped_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    base_score = db.Column(db.Float, nullable=True)
    temporal_score = db.Column(db.Float, nullable=True)
    oem_website_id = db.Column(db.Integer, db.ForeignKey('oem_websites.id'), nullable=False)
    oem_website = db.relationship('OEMWebsite', backref=db.backref('vulnerabilities', lazy=True))
    additional_details = db.Column(db.JSON, nullable=True) 

    def __init__(self, product_name, product_version, oem_name, severity_level, vulnerability, mitigation_strategy, published_date, unique_id, scraped_date, oem_website_id, additional_details=None):
        self.product_name = product_name
        self.product_version = product_version
        self.oem_name = oem_name
        self.severity_level = severity_level
        self.vulnerability = vulnerability
        self.mitigation_strategy = mitigation_strategy
        self.published_date = published_date
        self.unique_id = unique_id
        self.scraped_date = scraped_date
        self.oem_website_id = oem_website_id
        self.additional_details = additional_details


class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    email_sent_timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    status = db.Column(db.String(50), nullable=False)  # 'Pending', 'Sent', or 'Failed'

    # Relationships
    vulnerability = db.relationship('Vulnerabilities', backref=db.backref('alerts', lazy=True))
    user = db.relationship('User', backref=db.backref('alerts', lazy=True))

    def __init__(self, vulnerability_id, user_id, status='Pending'):
        self.vulnerability_id = vulnerability_id
        self.user_id = user_id
        self.status = status


class ScrapeDetail(db.Model):
    __tablename__ = 'scrape_details'

    id = db.Column(db.Integer, primary_key=True)
    scrape_started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    scrape_ended_at = db.Column(db.DateTime, nullable=True)
    scraped_websites = db.Column(db.Text, nullable=False)  # Comma-separated list of website URLs
    status = db.Column(db.String(50), nullable=False)  # 'In Progress', 'Completed', 'Failed'
    error_message = db.Column(db.Text, nullable=True)

    def __init__(self, scraped_websites, status='In Progress', error_message=None):
        self.scraped_websites = scraped_websites
        self.status = status
        self.error_message = error_message


class ReportedVulnerability(db.Model):
    __tablename__ = 'reported_vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Associate with user
    user = db.relationship('User', backref=db.backref('reported_vulnerabilities', lazy=True))
    
    product_name = db.Column(db.String(150), nullable=False)
    oem_name = db.Column(db.String(150), nullable=False)
    vulnerability_description = db.Column(db.Text, nullable=False)
    severity_level = db.Column(db.Float, nullable=False)  # Critical, High, Medium, etc.
    suggested_mitigation = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='Pending')  # 'Pending', 'Reviewed', 'Resolved'
    reported_date = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __init__(self, user_id, product_name, oem_name, vulnerability_description, severity_level, suggested_mitigation=None):
        self.user_id = user_id
        self.product_name = product_name
        self.oem_name = oem_name
        self.vulnerability_description = vulnerability_description
        self.severity_level = severity_level
        self.suggested_mitigation = suggested_mitigation


class Thread(db.Model):
    __tablename__ = 'threads'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Relationship
    user = db.relationship('User', backref=db.backref('threads', lazy=True))
    comments = db.relationship('Comment', backref='thread', lazy=True, cascade='all, delete-orphan')

    def __init__(self, title, user_id):
        self.title = title
        self.user_id = user_id


class Comment(db.Model):
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    upvotes = db.Column(db.Integer, default=0, nullable=False)
    downvotes = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    thread_id = db.Column(db.Integer, db.ForeignKey('threads.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Relationships
    user = db.relationship('User', backref=db.backref('comments', lazy=True))

    def __init__(self, text, thread_id, user_id):
        self.text = text
        self.thread_id = thread_id
        self.user_id = user_id
