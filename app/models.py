from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    
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
    
    oem_website_id = db.Column(db.Integer, db.ForeignKey('oem_websites.id'), nullable=False)
    oem_website = db.relationship('OEMWebsite', backref=db.backref('vulnerabilities', lazy=True))

    def __init__(self, product_name, product_version, oem_name, severity_level, vulnerability, mitigation_strategy, published_date, unique_id, scraped_date, oem_website_id):
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
