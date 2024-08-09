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

auth = Blueprint('auth', __name__)

load_dotenv()

# Ensure the upload directory exists
UPLOAD_FOLDER = 'static/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize Stripe with your secret key
stripe.api_key = os.getenv('STRIPE_API_KEY')

# Yagmail setup
YAGMAIL_USER = os.getenv('YAGMAIL_USER')
YAGMAIL_PASSWORD = os.getenv('YAGMAIL_PASSWORD')

if not YAGMAIL_USER or not YAGMAIL_PASSWORD:
    raise RuntimeError("YAGMAIL_USER and YAGMAIL_PASSWORD must be set as environment variables.")
yag = yagmail.SMTP(YAGMAIL_USER, YAGMAIL_PASSWORD)

@auth.route('/register', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def register():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    print(f"Received data: {data}")

    user = User.query.filter_by(email=data['email']).first()
    print(f"User found: {user}")

    if user:
        print(f"User with email {data['email']} already exists.")
        return jsonify({'message': 'A user with this email already exists'}), 400

    # Generate a token with the email and password
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    token = serializer.dumps({'email': data['email'], 'password': data['password'], 'username': data['name']}, salt='email-verification')

    # Generate the verification link
    verification_link = url_for('auth.verify_email', token=token, _external=True)

    # Send verification email
    subject = 'Verify your email'
    body = f'Please click the following link to verify your email and complete your registration: {verification_link}'
    yag.send(to=data['email'], subject=subject, contents=body)

    print("Verification email sent")
    return jsonify({'message': 'A verification email has been sent to your email address. Please verify your email to complete registration.'}), 200

@auth.route('/login', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def login():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
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
        profile_picture_url = f"http://localhost:5000/auth/uploads/{profile_picture_url}"
    
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
            'ad_account_id': ad_account.ad_account_id,
            'pixel_id': ad_account.pixel_id,
            'facebook_page_id': ad_account.facebook_page_id,
            'app_id': ad_account.app_id,
            'app_secret': ad_account.app_secret,
            'access_token': ad_account.access_token
        }), 200
    return jsonify({'message': 'Ad account not found or access denied'}), 404

@auth.route('/ad_accounts', methods=['GET'])
@cross_origin(supports_credentials=True)
@login_required
def get_ad_accounts():
    ad_accounts = AdAccount.query.filter_by(user_id=current_user.id).all()
    ad_accounts_data = [{'id': account.id, 'ad_account_id': account.ad_account_id, 'pixel_id': account.pixel_id, 'facebook_page_id': account.facebook_page_id, 'app_id': account.app_id, 'app_secret': account.app_secret, 'access_token': account.access_token, 'is_bound': account.is_bound} for account in ad_accounts]
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
        reset_link = url_for('auth.reset_password', token=token, _external=True)

        # Send reset password email
        subject = 'Password Reset Request'
        body = f'Please click the following link to reset your password: {reset_link}'
        yag.send(to=user.email, subject=subject, contents=body)

        return jsonify({'message': 'A password reset email has been sent to your email address.'}), 200
    except Exception as e:
        current_app.logger.error(f"Failed to send reset email: {e}")
        return jsonify({'message': 'Failed to send reset email.'}), 500

@auth.route('/reset_password/<token>', methods=['POST', 'GET', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def reset_password(token):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    try:
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        data = serializer.loads(token, salt='password-reset', max_age=3600)  # 1-hour expiration
        email = data.get('email')
        new_password = data.get('new_password')

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'message': 'Invalid user.'}), 400

        if user.reset_token_used:
            return jsonify({'message': 'This password reset link has already been used.'}), 400

        user.password = generate_password_hash(new_password)
        user.mark_token_as_used()  # Mark the token as used
        db.session.commit()

        # Redirect to the specified URL after successful reset
        return redirect('http://localhost:3000/login')  # Redirect to the registration page
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
        hashed_password = generate_password_hash(data['password'])
        new_user = User(username=data['username'], email=data['email'], password=hashed_password, is_active=True)
        db.session.add(new_user)
        db.session.commit()

        # Create a default ad account for the new user
        default_ad_account = AdAccount(user_id=new_user.id)
        db.session.add(default_ad_account)
        db.session.commit()

        login_user(new_user)  # Log the user in immediately after registration

        print("User verified and logged in successfully")
        return redirect('http://localhost:3000/')  # Redirect to localhost:3000 after verification

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
            return redirect('http://localhost:3000/')
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

