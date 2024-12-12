from .models import User, Vulnerabilities, Alert, db
from flask import jsonify, request
from flask_mail import Message
from . import mail

def send_alerts(id):

    vulnerability = Vulnerabilities.query.filter_by(email_sent = 0,oem_website_id=id).all()
    if not vulnerability:
        return jsonify({'message': 'Vulnerability not found'}), 404

    # Retrieve all users
    users = User.query.all()

    for user in users:
        if user.interested_in_product_categories:
            interested_categories = set(
                category.strip().lower()
                for category in user.interested_in_product_categories.split(',')
            )
            if vulnerability.oem_website.oem_name.lower() not in interested_categories:
                continue

        for vuln in vulnerability:
            # Create an alert for each user
            new_alert = Alert(vulnerability_id=vuln.id, user_id=user.id)
            db.session.add(new_alert)
            db.session.commit()

            # Send email to the user
            subject = f"New Vulnerability Alert: {vuln.product_name}"
            message_body = f"""
            -----------------------------------CVE SECURITY ALERT--------------------------------------------
            Dear {user.username},

            A new vulnerability has been identified:

            Product Name: {vuln.product_name}
            Version: {vuln.product_version}
            OEM: {vuln.oem_name}
            Severity Level: {vuln.severity_level}
            Vulnerability: {vuln.vulnerability}
            Mitigation Strategy: {vuln.mitigation_strategy}
            Published Date: {vuln.published_date.strftime('%B %Y')}

            Please take appropriate action!

            Best regards,
            Vulnerability tracker
            -------------------------------------------------------------------------------------------------
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