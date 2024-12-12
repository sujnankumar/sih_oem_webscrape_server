from .models import User, Vulnerabilities, Alert, db
from flask import jsonify, request
from flask_mail import Message
from . import mail
from sqlalchemy.orm import scoped_session, sessionmaker

def send_alerts(id,app):
    with app.app_context():
        session_factory = sessionmaker(bind=db.engine)
        scoped_session_factory = scoped_session(session_factory)
        session = scoped_session_factory()

        try:
            # Retrieve vulnerabilities with email_sent = 0 and matching oem_website_id
            vulnerabilities = session.query(Vulnerabilities).filter_by(email_sent=0, oem_website_id=id).all()
            print(vulnerabilities)
            if not vulnerabilities:
                return jsonify({'message': 'No vulnerabilities found'}), 404

            # Retrieve all users
            users = session.query(User).all()

            for user in users:
                if user.interested_in_product_categories:
                    interested_categories = set(
                        category.strip().lower()
                        for category in user.interested_in_product_categories.split(',')
                    )

                    # Check if the user is interested in the OEM name
                    if not any(
                        vuln.oem_website.oem_name.lower() in interested_categories
                        for vuln in vulnerabilities
                    ):  
                        print("User not interested in the OEM name")
                        continue

                for vuln in vulnerabilities:
                    # Create an alert for each user
                    new_alert = Alert(vulnerability_id=vuln.id, user_id=user.id)
                    session.add(new_alert)

                    # Send email to the user
                    subject = f"New Vulnerability Alert: {vuln.oem_website.oem_name}"
                    print(subject)
                    message_body = f"""
                    -----------------------------------CVE SECURITY ALERT--------------------------------------------
                    Dear {user.username},

                    A new vulnerability has been identified:

                    Product Names and Version: {vuln.product_name_version}
                    OEM: {vuln.oem_website.oem_name}
                    Severity Level: {vuln.severity_level}
                    Vulnerability: {vuln.vulnerability}
                    Mitigation Strategy: {vuln.remediation}
                    Published Date: {vuln.published_date.strftime('%B %Y')}

                    Please take appropriate action!

                    Best regards,
                    Vulnerability Tracker
                    -------------------------------------------------------------------------------------------------
                    """
                    try:
                        msg = Message(subject=subject, recipients=[user.email], body=message_body)
                        mail.send(msg)
                        
                        new_alert.status = 'Sent'
                    except Exception as e:
                        new_alert.status = 'Failed'
                        print(f"Failed to send email to {user.email}: {e}")

                    # Mark the vulnerability as email_sent
                    vuln.email_sent = 1

            # Commit all changes in a single transaction
            session.commit()
        except  Exception as e:
            session.rollback()