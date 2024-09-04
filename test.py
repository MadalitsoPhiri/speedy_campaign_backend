import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Replace with your Outlook email and the generated app password
OUTLOOK_USER = 'support@quickcampaigns.io'
OUTLOOK_PASSWORD = 'your_app_password_here'  # Replace with the app password

def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg['From'] = OUTLOOK_USER
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        # Establish a secure session with Outlook's SMTP server
        server = smtplib.SMTP('smtp.office365.com', 587)
        server.starttls()
        server.login(OUTLOOK_USER, OUTLOOK_PASSWORD)
        text = msg.as_string()
        server.sendmail(OUTLOOK_USER, to_email, text)
        server.quit()

        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Usage example
send_email('isaacnewton@example.com', 'Test Subject', 'This is a test email body')
