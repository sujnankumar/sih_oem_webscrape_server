from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def get_id(self):
        """Override `get_id` to return a string (required by Flask-Login)."""
        return str(self.id)


# New model for storing OEM website scraped data
class OEMData(db.Model):
    __tablename__ = 'oem_data'

    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(150), nullable=False)
    product_version = db.Column(db.String(100), nullable=True)
    oem_name = db.Column(db.String(150), nullable=False)
    severity_level = db.Column(db.String(50), nullable=False)  # Critical or High
    vulnerability = db.Column(db.Text, nullable=False)
    mitigation_strategy = db.Column(db.Text, nullable=False)
    published_date = db.Column(db.Date, nullable=False)
    unique_id = db.Column(db.String(50), unique=True, nullable=False)  # CVE ID or similar
    scraped_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())  # New field

    def __init__(self, product_name, product_version, oem_name, severity_level, vulnerability, mitigation_strategy, published_date, unique_id, scraped_date):
        self.product_name = product_name
        self.product_version = product_version
        self.oem_name = oem_name
        self.severity_level = severity_level
        self.vulnerability = vulnerability
        self.mitigation_strategy = mitigation_strategy
        self.published_date = published_date
        self.unique_id = unique_id
        self.scraped_date = scraped_date


class Subscriber(db.Model):
    __tablename__ = 'subscribers'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    subscribed_date = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __init__(self, email, subscribed_date):
        self.email = email
        self.subscribed_date = subscribed_date

