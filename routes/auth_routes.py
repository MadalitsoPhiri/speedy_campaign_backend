from flask import Blueprint, request, jsonify, send_from_directory, current_app, url_for, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import User, AdAccount, db
from flask_login import login_user, current_user, logout_user, login_required
from flask_cors import cross_origin
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import redirect
import yagmail
from dotenv import load_dotenv
import os
import requests
from datetime import datetime, timedelta
import stripe
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import uuid

auth = Blueprint('auth', __name__)

load_dotenv()

# Ensure the upload directory exists
UPLOAD_FOLDER = 'static/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize Stripe with your secret key
stripe.api_key = os.getenv('STRIPE_API_KEY')

REACT_APP_API_URL=os.getenv('REACT_APP_API_URL')
BACKEND_API_URL=os.getenv('BACKEND_API_URL')

# Yagmail setup
YAGMAIL_USER = os.getenv('EMAIL_USER')
YAGMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

if not YAGMAIL_USER or not YAGMAIL_PASSWORD:
    raise RuntimeError("YAGMAIL_USER and YAGMAIL_PASSWORD must be set as environment variables.")
yag = yagmail.SMTP(YAGMAIL_USER, YAGMAIL_PASSWORD)

# Load SMTP credentials from environment variables
smtp_user = os.getenv('EMAIL_USER')  # Full email address
smtp_password = os.getenv('EMAIL_PASSWORD')  # App password or account password

if not smtp_user or not smtp_password:
    raise RuntimeError("SMTP_USER and SMTP_PASSWORD must be set as environment variables.")

# Outlook SMTP configuration
smtp_server = "smtp.office365.com"
smtp_port = 587

def verify_recaptcha_token(recaptcha_token):
    """
    Verify the reCAPTCHA token with Google's reCAPTCHA API.
    
    Args:
        recaptcha_token (str): The token from the client-side reCAPTCHA.

    Returns:
        bool: True if the token is valid, False if invalid or not provided.
    """
    if not recaptcha_token:
        print("No reCAPTCHA token provided. Skipping verification.")
        return True  # Allow requests without reCAPTCHA if not enforced
    
    secret_key = os.getenv('RECAPTCHA_SECRET_KEY')

    if not secret_key:
        print("Error: RECAPTCHA_SECRET_KEY is missing in the app configuration.")
        return False  # Fail verification if secret key is missing

    verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    payload = {'secret': secret_key, 'response': recaptcha_token}
    
    try:
        response = requests.post(verify_url, data=payload)
        result = response.json()
        print(f"reCAPTCHA verification result: {result}")
        return result.get('success', False)
    except Exception as e:
        print(f"Error verifying reCAPTCHA token: {e}")
        return False

@auth.route('/register', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def register():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()

    # Verify the reCAPTCHA token
    recaptcha_token = data.get('recaptcha')
    if not verify_recaptcha_token(recaptcha_token):
        return jsonify({'message': 'Invalid reCAPTCHA token. Please verify you are human.'}), 400

    user = User.query.filter_by(email=data['email']).first()
    print(f"User found: {user}")

    if user:
        print(f"User with email {data['email']} already exists.")
        return jsonify({'message': 'A user with this email already exists'}), 400

    # Generate a token with the email and password
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    token = serializer.dumps({'email': data['email'], 'password': hashed_password, 'username': data['name']}, salt='email-verification')

    # Generate the verification link
    verification_link = url_for('auth.verify_email', token=token, _external=True)

    # Email details
    subject = 'Welcome to QuickCampaigns – Verify Your Email'
    to_email = data['email']
    html_content =f"""
        <!DOCTYPE html>
        <html>
        <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="font-family: 'Poppins', sans-serif; background-color: #f9f9f9; margin: 0; padding: 0; color: #333;">
            <div style="max-width: 640px; margin: 20px auto; border: 3px solid #ccc; background-color: #ffffff; padding: 20px; box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);">
                <div style="max-width: 600px; margin: 0 auto;">
                    <div style="text-align: center; font-size: 16px; color: #555;">
                        <p style="margin: 0 0 20px; color: #333;">Hi {data['name']},</p>
                        <p style="margin: 0 0 20px; color: #555;">
                            Your <a href="https://quickcampaigns.io" style="color: #5356FF; text-decoration: none; font-weight: bold;">QuickCampaigns</a> account is live! Start creating lightning-fast Facebook Ads campaigns today.
                        </p>
                        <p style="margin: 30px 0; color: #333;">Click the button below to verify your email and get started:</p>
                        <a href="{verification_link}" 
                        style="display: inline-block; padding: 12px 30px; font-size: 16px; font-weight: 500; color: #FFFFFF; text-decoration: none; border-radius: 8px; background-color: #5356FF;">
                        Verify Account
                        </a>
                        <p style="margin: 20px 0; font-size: 15px; color: #777;">Cheers,<br>The QuickCampaigns Team</p>
                    </div>
                    <div style="font-size: 14px; color: #999; text-align: center; margin-top: 20px;">
                        <p style="margin: 0;">&copy; {datetime.utcnow().year} QuickCampaigns. All rights reserved.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """



    # Create the email message
    msg = MIMEText(html_content, "html")
    msg["From"] = smtp_user
    msg["To"] = to_email
    msg["Subject"] = subject
    msg["Message-ID"] = f"<{uuid.uuid4()}@quickcampaigns.io>"
    msg["X-Priority"] = "3"
    msg["X-Entity-Ref-ID"] = f"{uuid.uuid4()}"
    msg["X-Mailer"] = "QuickCampaignsMailer"

    # Send the email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.set_debuglevel(1)  # Enable verbose output for debugging
            server.starttls()  # Start TLS encryption
            server.login(smtp_user, smtp_password)  # Authenticate with the SMTP server
            server.send_message(msg)  # Send the email
        print("Verification email sent")
    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP Authentication Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

    return jsonify({'message': 'A verification email has been sent to your email address. Please verify your email to complete registration.'}), 200

@auth.route('/login', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def login():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()

    # Verify the reCAPTCHA token
    recaptcha_token = data.get('recaptcha')
    if not verify_recaptcha_token(recaptcha_token):
        return jsonify({'message': 'Invalid reCAPTCHA token. Please verify you are human.'}), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify({'message': 'User does not exist'}), 401

    if not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Incorrect password'}), 401

    if not user.is_active:
        return jsonify({'message': 'User account is inactive'}), 401

    remember = data.get('remember', False)
    login_user(user, remember=remember)
    print(f"User {user.username} logged in. Is authenticated? {current_user.is_authenticated()}")
    return jsonify({'message': 'Logged in successfully', 'user': {'username': user.username, 'email': user.email}}), 200

@auth.route('/logout', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@login_required
def logout():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    logout_user()
    return jsonify({"message": "Successfully logged out"}), 200

@auth.route('/current_user', methods=['GET', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def current_user_route():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    if current_user.is_authenticated:
        current_app.logger.info(f"User {current_user.username} is authenticated.")
        return jsonify({'user': {'username': current_user.username, 'email': current_user.email}}), 200
    else:
        current_app.logger.warning("User not authenticated. Returning 401.")
        return jsonify({'user': None}), 401
    
@auth.route('/google', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def google_login():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    token = data.get('token')
    remember = data.get('remember', False)
    print(f"Received Google access token: {token}")

    try:
        # Fetch user info from Google using the access token
        userinfo_response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {token}'}
        )
        userinfo = userinfo_response.json()
        print(f"User info from Google: {userinfo}")

        email = userinfo['email']
        name = userinfo.get('name', email)

        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        if user is None:
            # Create new user
            user = User(username=name, email=email, password='', is_active=True)
            db.session.add(user)
            db.session.commit()
            print("New user created and added to the database.")
            
            # Create a default ad account for the new user
            default_ad_account = AdAccount(user_id=user.id, subscription_start_date=None, subscription_end_date=None)
            db.session.add(default_ad_account)
            db.session.commit()
            print("Default ad account created for new Google user.")

        # If user exists but has no ad account, create one
        elif not user.ad_accounts:
            default_ad_account = AdAccount(user_id=user.id, subscription_start_date=None, subscription_end_date=None)
            db.session.add(default_ad_account)
            db.session.commit()
            print("Default ad account created for existing Google user with no ad account.")

        login_user(user, remember=remember)
        print(f"User {user.username} logged in successfully.")

        return jsonify({'message': 'Logged in successfully', 'user': {'username': user.username, 'email': user.email}}), 200

    except Exception as e:
        print(f"Failed to fetch user info: {e}")
        return jsonify({'message': str(e)}), 401

@auth.route('/uploads/<filename>')
def uploaded_file(filename):
    print(f"Serving file from: {os.path.join(UPLOAD_FOLDER, filename)}")  # Log the path being requested
    return send_from_directory(UPLOAD_FOLDER, filename)

@auth.route('/profile', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
@login_required
def profile():
    if request.method == 'POST':
        data = request.form
        file = request.files.get('profile_picture')

        current_user.username = data['username']
        
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            current_user.profile_picture = filename  # Store only the filename
            print(f"Profile picture saved: {filename}")  # Log the filename saved in the database

        db.session.commit()
        return jsonify({'message': 'Profile updated successfully'}), 200

    profile_picture_url = current_user.profile_picture
    if profile_picture_url:
        profile_picture_url = f"{BACKEND_API_URL}/auth/uploads/{profile_picture_url}"
    
    print(f"Profile picture URL being sent to frontend: {profile_picture_url}")  # Log the URL being sent to the frontend

    return jsonify({
        'user': {
            'username': current_user.username,
            'email': current_user.email,
            'profile_picture': profile_picture_url,
            'ad_accounts': [{'id': account.id, 'ad_account_id': account.ad_account_id, 'pixel_id': account.pixel_id, 'facebook_page_id': account.facebook_page_id, 'app_id': account.app_id, 'app_secret': account.app_secret, 'access_token': account.access_token, 'is_bound': account.is_bound} for account in current_user.ad_accounts]
        }
    }), 200

@auth.route('/ad_account', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def update_ad_account():
    data = request.json
    account_id = data['id']
    ad_account = AdAccount.query.get(account_id)
    
    if ad_account and not ad_account.is_bound:
        ad_account.ad_account_id = data['ad_account_id']
        ad_account.pixel_id = data['pixel_id']
        ad_account.facebook_page_id = data['facebook_page_id']
        ad_account.app_id = data['app_id']
        ad_account.app_secret = data['app_secret']
        ad_account.access_token = data['access_token']
        ad_account.business_manager_id = data.get('business_manager_id')
        # Fetch ad account name from Facebook
        try:
            fb_response = requests.get(
                f'https://graph.facebook.com/v10.0/{data["ad_account_id"]}?fields=name&access_token={data["access_token"]}'
            )
            fb_data = fb_response.json()
            ad_account.name = fb_data['name']  # Store the ad account name in the database
        except requests.exceptions.RequestException as e:
            return jsonify({'message': 'Failed to fetch ad account name from Facebook'}), 400

        ad_account.is_bound = True
        db.session.commit()
        return jsonify({'message': 'Ad account updated successfully'}), 200
    else:
        return jsonify({'message': 'Ad account already bound or not found'}), 400

@auth.route('/ad_account/<int:id>', methods=['GET'])
@cross_origin(supports_credentials=True)
@login_required
def get_ad_account(id):
    ad_account = AdAccount.query.get(id)
    if ad_account and ad_account.user_id == current_user.id:
        return jsonify({
            'id': ad_account.id,
            'ad_account_id': ad_account.ad_account_id,
            'pixel_id': ad_account.pixel_id,
            'facebook_page_id': ad_account.facebook_page_id,
            'app_id': ad_account.app_id,
            'app_secret': ad_account.app_secret,
            'access_token': ad_account.access_token,
            'is_bound': ad_account.is_bound,  # Include is_bound in the response
            'name': ad_account.name,  # Include the name field in the response
            'business_manager_id': ad_account.business_manager_id
        }), 200
    return jsonify({'message': 'Ad account not found or access denied'}), 404

@auth.route('/ad_accounts', methods=['GET'])
@cross_origin(supports_credentials=True)
@login_required
def get_ad_accounts():
    ad_accounts = AdAccount.query.filter_by(user_id=current_user.id).order_by(AdAccount.id.asc()).all()
    ad_accounts_data = [{'id': account.id, 'ad_account_id': account.ad_account_id, 'pixel_id': account.pixel_id, 'facebook_page_id': account.facebook_page_id, 'app_id': account.app_id, 'app_secret': account.app_secret, 'access_token': account.access_token, 'is_bound': account.is_bound, 'business_manager_id': account.business_manager_id} for account in ad_accounts]
    return jsonify({'ad_accounts': ad_accounts_data}), 200

@auth.route('/delete_ad_account', methods=['DELETE'])
@cross_origin(supports_credentials=True)
@login_required
def delete_ad_account():
    data = request.get_json()
    ad_account_id = data.get('ad_account_id')

    # Find the ad account by ID and verify that it belongs to the current user
    ad_account = AdAccount.query.filter_by(id=ad_account_id, user_id=current_user.id).first()

    if not ad_account:
        return jsonify({'error': 'Ad account not found or does not belong to the current user'}), 404

    # Check if it's the last ad account
    user_ad_accounts = AdAccount.query.filter_by(user_id=current_user.id).all()
    if len(user_ad_accounts) <= 1:
        return jsonify({'error': 'Cannot delete the last ad account'}), 400

    # Delete the ad account
    db.session.delete(ad_account)
    db.session.commit()

    return jsonify({'message': 'Ad account deleted successfully'}), 200

@auth.route('/ad_account/<int:id>/config', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def update_ad_account_config(id):
    data = request.get_json()
    ad_account = AdAccount.query.get(id)
    
    if ad_account and ad_account.user_id == current_user.id:
        ad_account.set_default_config(data)  # If using Text type, use json.dumps(data)
        db.session.commit()
        return jsonify({'message': 'Ad account configuration updated successfully'}), 200
    return jsonify({'message': 'Ad account not found or access denied'}), 404

@auth.route('/ad_account/<int:id>/config', methods=['GET'])
@cross_origin(supports_credentials=True)
@login_required
def get_ad_account_config(id):
    ad_account = AdAccount.query.get(id)
    if ad_account and ad_account.user_id == current_user.id:
        config = ad_account.get_default_config()  # If using Text type, use json.loads(config)
        return jsonify(config), 200
    return jsonify({'message': 'Ad account not found or access denied'}), 404

@auth.route('/subscription', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def manage_subscription():
    data = request.get_json()
    ad_account_id = data.get('ad_account_id')
    plan = data.get('plan')

    # Find the ad account associated with the current user
    ad_account = AdAccount.query.filter_by(id=ad_account_id, user_id=current_user.id).first()

    if not ad_account:
        return jsonify({'error': 'Ad account not found or does not belong to the current user'}), 404

    # Update the subscription plan for the specific ad account
    if plan == 'Free Trial':
        ad_account.subscription_plan = 'Free Trial'
        ad_account.subscription_start_date = datetime.utcnow()
        ad_account.subscription_end_date = datetime.utcnow() + timedelta(days=5)
        ad_account.is_subscription_active = True
    elif plan == 'Professional':
        ad_account.subscription_plan = 'Professional'
        ad_account.subscription_start_date = datetime.utcnow()
        ad_account.subscription_end_date = datetime.utcnow() + timedelta(days=30)  # 30 days duration
        ad_account.is_subscription_active = True
    elif plan == 'Enterprise':
        ad_account.subscription_plan = 'Enterprise'
        ad_account.subscription_start_date = datetime.utcnow()
        ad_account.subscription_end_date = datetime.utcnow() + timedelta(days=30)  # 30 days duration
        ad_account.is_subscription_active = True
    else:
        return jsonify({'error': 'Invalid plan selected'}), 400

    db.session.commit()

    # Update the running plan based on the status of all ad accounts
    update_running_plan(current_user)

    return jsonify({'message': f'Subscribed {ad_account_id} to {plan} plan'}), 200

def update_running_plan(user):
    active_subscriptions = [account for account in user.ad_accounts if account.is_subscription_active]
    if not active_subscriptions:
        user.subscription_plan = None
    elif len(active_subscriptions) > 0:
        user.subscription_plan = 'Enterprise' if 'Enterprise' in [account.subscription_plan for account in active_subscriptions] else 'Professional'
    db.session.commit()

@auth.route('/forgot_password', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def forgot_password():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    print(data)

    # Use the correct field names based on the provided data structure
    if 'newPassword' not in data:
        return jsonify({'message': 'New password is required in the request payload.'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'message': 'No user with that email address exists.'}), 400

    try:
        # Reset token usage status
        user.reset_token_used = False
        db.session.commit()

        # Generate a token that includes the user's email and new password
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        token = serializer.dumps({'email': user.email, 'new_password': data['newPassword']}, salt='password-reset')

        # Generate a reset link
        reset_link = f"{REACT_APP_API_URL}/reset-password?token={token}"

        # Send reset password email
        subject = ' Reset Your Password'
        to_email = user.email
        html_content =f"""
            <!DOCTYPE html>
            <html>
            <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body style="font-family: 'Poppins', sans-serif; background-color: #f9f9f9; margin: 0; padding: 0; color: #333;">
                <div style="max-width: 640px; margin: 20px auto; border: 3px solid #ccc; background-color: #ffffff; padding: 20px; box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);">
                    <div style="max-width: 600px; margin: 0 auto;">
                        <div style="text-align: center; font-size: 16px; color: #555;">
                            <p style="margin: 0 0 20px; color: #333;">Hi {user.username},</p>
                            <p style="margin: 0 0 20px; color: #555;">
                                Need to reset your password? No problem.
                            </p>
                            <p style="margin: 30px 0; color: #333;">Click the button below to set a new password:</p>
                            <a href="{reset_link}" 
                            style="display: inline-block; padding: 12px 30px; font-size: 16px; font-weight: 500; color: #FFFFFF; text-decoration: none; border-radius: 8px; background-color: #5356FF;">
                            Reset password
                            </a>
                            <p style="margin: 20px 0 20px; color: #555;">
                                If you didn’t request this, you can safely ignore this email.
                            </p>
                            <p style="margin: 20px 0; font-size: 15px; color: #777;">Cheers,<br>The QuickCampaigns Team</p>
                        </div>
                        <div style="font-size: 14px; color: #999; text-align: center; margin-top: 20px;">
                            <p style="margin: 0;">&copy; {datetime.utcnow().year} QuickCampaigns. All rights reserved.</p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """

        # Create the email message
        msg = MIMEText(html_content, "html")
        msg["From"] = smtp_user
        msg["To"] = to_email
        msg["Subject"] = subject
        msg["Message-ID"] = f"<{uuid.uuid4()}@quickcampaigns.io>"
        msg["X-Priority"] = "3"
        msg["X-Entity-Ref-ID"] = f"{uuid.uuid4()}"
        msg["X-Mailer"] = "QuickCampaignsMailer"

        # Send the email
        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.set_debuglevel(1)  # Enable verbose output for debugging
                server.starttls()  # Start TLS encryption
                server.login(smtp_user, smtp_password)  # Authenticate with the SMTP server
                server.send_message(msg)  # Send the email
            print("password reset email sent")
        except smtplib.SMTPAuthenticationError as e:
            print(f"SMTP Authentication Error: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

        return jsonify({'message': 'A password reset email has been sent to your email address.'}), 200
    except Exception as e:
        current_app.logger.error(f"Failed to send reset email: {e}")
        return jsonify({'message': 'Failed to send reset email.'}), 500

@auth.route('/reset_password', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def reset_password():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    token = data.get('token')
    new_password = data.get('newPassword')

    if not token or not new_password:
        return jsonify({'message': 'Token and new password are required.'}), 400

    try:
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        token_data = serializer.loads(token, salt='password-reset', max_age=3600)  # 1-hour expiration
        email = token_data['email']

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'message': 'Invalid token or user does not exist.'}), 400

        # Update the user's password
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()

        return jsonify({'message': 'Password reset successfully.'}), 200
    except Exception as e:
        return jsonify({'message': 'The password reset link is invalid or has expired.'}), 400

@auth.route('/verify_email/<token>', methods=['GET'])
@cross_origin(supports_credentials=True)
def verify_email(token):
    try:
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        data = serializer.loads(token, salt='email-verification', max_age=3600)  # 1-hour expiration

        # Check if the user already exists
        email = data['email']
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'message': 'This email is already verified.'}), 400

        # Create the new user
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        new_user = User(username=data['username'], email=data['email'], password=hashed_password, is_active=True)
        db.session.add(new_user)
        db.session.commit()

        # Create a default ad account for the new user
        default_ad_account = AdAccount(user_id=new_user.id)
        db.session.add(default_ad_account)
        db.session.commit()

        login_user(new_user)  # Log the user in immediately after registration

        print("User verified and logged in successfully")
        return redirect(REACT_APP_API_URL)  # Redirect to localhost:3000 after verification

    except SignatureExpired:
        return jsonify({'message': 'The verification link has expired.'}), 400
    except BadSignature:
        return jsonify({'message': 'Invalid verification link.'}), 400

@auth.route('/auto-login', methods=['GET'])
def auto_login():
    session_id = request.args.get('session_id')

    # Retrieve the Stripe session to get user info
    try:
        session = stripe.checkout.Session.retrieve(session_id)
        customer_email = session.get('customer_details', {}).get('email')

        # Find the user in your database
        user = User.query.filter_by(email=customer_email).first()
        if user:
            login_user(user)
            # Redirect to the frontend URL directly
            return redirect(REACT_APP_API_URL)
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth.route('/verify_ad_account', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def verify_ad_account():
    data = request.get_json()
    ad_account_id = data.get('ad_account_id')
    access_token = data.get('access_token')
    print(data)

    try:
        response = requests.get(
            f'https://graph.facebook.com/v15.0/{ad_account_id}',
            params={'access_token': access_token}
        )
        response.raise_for_status()
        return jsonify({"valid": True}), 200
    except requests.exceptions.HTTPError as err:
        return jsonify({"valid": False, "error": str(err)}), 400

@auth.route('/verify_pixel_id', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def verify_pixel_id():
    data = request.get_json()
    pixel_id = data.get('pixel_id')
    access_token = data.get('access_token')

    try:
        response = requests.get(
            f'https://graph.facebook.com/v15.0/{pixel_id}',
            params={'access_token': access_token}
        )
        response.raise_for_status()
        return jsonify({"valid": True}), 200
    except requests.exceptions.HTTPError as err:
        return jsonify({"valid": False, "error": str(err)}), 400

@auth.route('/verify_facebook_page_id', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def verify_facebook_page_id():
    data = request.get_json()
    facebook_page_id = data.get('facebook_page_id')
    access_token = data.get('access_token')

    try:
        response = requests.get(
            f'https://graph.facebook.com/v15.0/{facebook_page_id}',
            params={'access_token': access_token}
        )
        response.raise_for_status()
        return jsonify({"valid": True}), 200
    except requests.exceptions.HTTPError as err:
        return jsonify({"valid": False, "error": str(err)}), 400

@auth.route('/verify_app_id', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def verify_app_id():
    data = request.get_json()
    app_id = data.get('app_id')
    access_token = data.get('access_token')

    try:
        response = requests.get(
            f'https://graph.facebook.com/v15.0/{app_id}',
            params={'access_token': access_token}
        )
        response.raise_for_status()
        return jsonify({"valid": True}), 200
    except requests.exceptions.HTTPError as err:
        return jsonify({"valid": False, "error": str(err)}), 400

@auth.route('/verify_access_token', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def verify_access_token():
    data = request.get_json()
    access_token = data.get('access_token')

    try:
        response = requests.get(
            f'https://graph.facebook.com/debug_token',
            params={'input_token': access_token, 'access_token': access_token}
        )
        response.raise_for_status()
        return jsonify({"valid": True}), 200
    except requests.exceptions.HTTPError as err:
        return jsonify({"valid": False, "error": str(err)}), 400

@auth.route('/verify_app_secret', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def verify_app_secret():
    data = request.get_json()
    access_token = data.get('access_token')
    app_secret = data.get('app_secret')

    # Validate input
    if not access_token or not app_secret:
        return jsonify({"valid": False, "error": "Access token and App secret are required"}), 400

    # Generate appsecret_proof
    appsecret_proof = generate_app_secret_proof(access_token, app_secret)

    try:
        response = requests.get(
            f'https://graph.facebook.com/v15.0/me',
            params={'access_token': access_token, 'appsecret_proof': appsecret_proof}
        )
        response.raise_for_status()
        return jsonify({"valid": True}), 200
    except requests.exceptions.HTTPError as err:
        return jsonify({"valid": False, "error": str(err)}), 400

def generate_app_secret_proof(access_token, app_secret):
    import hmac
    import hashlib
    return hmac.new(app_secret.encode('utf-8'), access_token.encode('utf-8'), hashlib.sha256).hexdigest()

@auth.route('/facebook', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def facebook_login():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    access_token = data.get('accessToken')
    name = data.get('name')
    email = data.get('email')

    try:
        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        if user is None:
            # Create new user
            user = User(username=name, email=email, password='', is_active=True)
            db.session.add(user)
            db.session.commit()

            # Create a default ad account for the new user
            default_ad_account = AdAccount(user_id=user.id)
            db.session.add(default_ad_account)
            db.session.commit()

        # If user exists but has no ad account, create one
        elif not user.ad_accounts:
            default_ad_account = AdAccount(user_id=user.id)
            db.session.add(default_ad_account)
            db.session.commit()

        login_user(user)
        return jsonify({'message': 'Logged in successfully', 'user': {'username': user.username, 'email': user.email}}), 200

    except Exception as e:
        print(f"Failed to login with Facebook: {e}")
        return jsonify({'message': str(e)}), 401

from flask import redirect, url_for

@auth.route('/update-user', methods=['POST'])
@cross_origin(supports_credentials=True)
def update_user():
    try:
        data = request.get_json()
        original_email = data.get('originalEmail')  # Track user's original email
        updated_email = data.get('updatedEmail')  # Email entered by user in form
        new_username = data.get('username')
        new_password = data.get('password')

        if not original_email or not new_username or not new_password:
            return jsonify({'error': 'Original email, username, and password are required'}), 400

        user = User.query.filter_by(email=original_email).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Update email only if it's different from the original
        if user.email != updated_email:
            user.email = updated_email

        user.username = new_username
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')

        db.session.commit()

        login_user(user, remember=True)

        current_app.logger.info(f"User {original_email} updated profile successfully.")

        return jsonify({
            'message': 'User profile updated successfully.',
            'redirect_url': f"{REACT_APP_API_URL}"
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error updating user profile: {str(e)}")
        return jsonify({'error': 'An error occurred while updating user profile'}), 500
