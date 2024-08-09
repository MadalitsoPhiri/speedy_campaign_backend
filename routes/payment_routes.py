from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from subscription_utils import start_free_trial
from models import db, User, AdAccount
import stripe
from datetime import datetime, timedelta
from flask_cors import cross_origin
from dotenv import load_dotenv
import os
from flask_login import login_user
import logging
import requests
import secrets
import string
from werkzeug.security import generate_password_hash

# Initialize the Blueprint for payment routes
payment = Blueprint('payment', __name__)

load_dotenv()

stripe.verify_ssl_certs = False

# Initialize Stripe with your secret key
stripe.api_key = os.getenv('STRIPE_API_KEY')

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@payment.route('/create-checkout-session', methods=['POST'])
@login_required
@cross_origin(supports_credentials=True)
def create_checkout_session():
    data = request.get_json()
    current_app.logger.info(f"Received data: {data}")

    plan_type = data.get('plan')
    ad_account_id = data.get('ad_account_id')

    current_app.logger.info(f"Plan Type: {plan_type}, Ad Account ID: {ad_account_id}")

    ad_account = AdAccount.query.filter_by(id=ad_account_id, user_id=current_user.id).first()

    if not ad_account:
        current_app.logger.error(f"Ad account not found or does not belong to the current user. Ad Account ID: {ad_account_id}")
        return jsonify({'error': 'Ad account not found or does not belong to the current user'}), 404

    # Check if the user is on a Professional plan and is upgrading to Enterprise
    if ad_account.subscription_plan == 'Professional' and ad_account.is_subscription_active and plan_type == 'Enterprise':
        current_app.logger.info(f"User {current_user.id} is upgrading from Professional to Enterprise plan without creating a new checkout session.")
        
        # Update the subscription plan type without modifying the dates
        ad_account.subscription_plan = 'Enterprise'
        db.session.commit()

        # Update user subscription plan type without modifying the dates
        user = User.query.get(current_user.id)
        user.subscription_plan = 'Enterprise'
        db.session.commit()

        return jsonify({'message': 'Plan updated to Enterprise'}), 200

    if plan_type == 'Professional':
        price_id = 'price_1Pj3pZ01UFm1325diqAaUr32'
    elif plan_type == 'Enterprise':
        price_id = 'price_1Pj3pq01UFm1325dyNHzvDDX'
    elif plan_type == 'Free Trial':
        if current_user.has_used_free_trial:
            current_app.logger.warning(f"User has already used the Free Trial. User ID: {current_user.id}")
            return jsonify({'error': 'Free Trial already used, please choose a different plan'}), 400
        price_id = 'price_1Pj3pZ01UFm1325diqAaUr32'
    else:
        current_app.logger.error(f"Invalid plan type received: {plan_type}")
        return jsonify({'error': 'Invalid plan'}), 400

    current_app.logger.info(f"Price ID set to: {price_id}")

    try:
        # Create session without a trial
        if plan_type != 'Free Trial':
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url="http://localhost:3000/pricing-section",
                cancel_url="http://localhost:3000/pricing-section",
                metadata={
                    'user_id': current_user.id, 
                    'ad_account_id': ad_account.id,
                    'plan_type': plan_type,
                    'is_anonymous': False
                }
            )
        else:
            # Create session with a trial for Free Trial
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                subscription_data={'trial_period_days': 5},
                success_url="http://localhost:3000/pricing-section",
                cancel_url="http://localhost:3000/pricing-section",
                metadata={
                    'user_id': current_user.id, 
                    'ad_account_id': ad_account.id,
                    'plan_type': plan_type,
                    'is_anonymous': False
                }
            )

        current_app.logger.info(f"Stripe checkout session created successfully. Session ID: {session.id}")

        return jsonify({'sessionId': session.id}), 200

    except Exception as e:
        current_app.logger.error(f"Stripe API error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for i in range(length))

def handle_checkout_session(session):
    plan_type = session['metadata']['plan_type']
    is_anonymous = session['metadata']['is_anonymous']

    if is_anonymous:
        email = session.get('customer_details', {}).get('email')
        name = session.get('customer_details', {}).get('name')

        if not email:
            current_app.logger.error("No email found for anonymous checkout.")
            return

        # Check if the user already exists
        user = User.query.filter_by(email=email).first()

        if not user:
            # Generate a random password
            random_password = generate_random_password()
            hashed_password = generate_password_hash(random_password, method='pbkdf2:sha256')

            # Create a new user account with hashed password
            user = User(email=email, username=name, password=hashed_password, is_active=True)
            user.subscription_plan = plan_type
            db.session.add(user)
            db.session.commit()
            current_app.logger.info(f"Created new user for anonymous checkout with email: {email}")

            # Create a new ad account for the user
            ad_account = AdAccount(user_id=user.id, subscription_plan=plan_type, is_subscription_active=True)
            ad_account.subscription_start_date = datetime.utcnow()
            ad_account.subscription_end_date = datetime.utcnow() + timedelta(days=30)
            ad_account.stripe_subscription_id = session['subscription']
            db.session.add(ad_account)
            db.session.commit()
            current_app.logger.info(f"Created new ad account for user {user.id}")

            if plan_type == 'Free Trial':
                ad_account.subscription_end_date = datetime.utcnow() + timedelta(days=5)
                start_free_trial(user)
        else:
            # Normal checkout handling for logged-in users
            handle_normal_checkout(user, session, plan_type)

    else:
        # Normal checkout handling for logged-in users
        user_id = session['metadata']['user_id']
        ad_account_id = session['metadata']['ad_account_id']

        user = User.query.get(user_id)
        ad_account = AdAccount.query.get(ad_account_id)

        if user and ad_account:
            handle_normal_checkout(user, session, plan_type)

def log_user_and_ad_accounts(user):
    # Log user information
    current_app.logger.info(f"User ID: {user.id}, Email: {user.email}, Username: {user.username}, Subscription Plan: {user.subscription_plan}")

    # Fetch and log all ad accounts for this user
    ad_accounts = AdAccount.query.filter_by(user_id=user.id).all()
    for ad_account in ad_accounts:
        current_app.logger.info(
            f"Ad Account ID: {ad_account.id}, Subscription Plan: {ad_account.subscription_plan}, "
            f"Is Active: {ad_account.is_subscription_active}, "
            f"Start Date: {ad_account.subscription_start_date}, End Date: {ad_account.subscription_end_date}, "
            f"Stripe Subscription ID: {ad_account.stripe_subscription_id}"
        )

def handle_normal_checkout(user, session, plan_type):
    ad_account_id = session['metadata']['ad_account_id']
    ad_account = AdAccount.query.get(ad_account_id)

    if user.subscription_plan == 'Enterprise' and plan_type == 'Professional':
        # Delete all ad accounts for downgrade to Professional
        AdAccount.query.filter_by(user_id=user.id).delete()
        current_app.logger.info(f"Deleted all ad accounts for user {user.id} as they are downgrading to Professional plan")

        # Create a new ad account for the Professional plan
        ad_account = AdAccount(user_id=user.id, subscription_plan=plan_type, is_subscription_active=True)
        ad_account.subscription_start_date = datetime.utcnow()
        ad_account.subscription_end_date = datetime.utcnow() + timedelta(days=30)
        ad_account.stripe_subscription_id = session['subscription']
        db.session.add(ad_account)
    else:
        # Normal subscription handling
        if ad_account.stripe_subscription_id and ad_account.is_subscription_active:
            try:
                stripe.Subscription.delete(ad_account.stripe_subscription_id)
                current_app.logger.info(f"Cancelled existing subscription for ad account {ad_account.id}")
            except stripe.error.InvalidRequestError as e:
                current_app.logger.error(f"Stripe API error while canceling subscription: {e}")
                if "No such subscription" in str(e):
                    current_app.logger.warning(f"Subscription {ad_account.stripe_subscription_id} not found.")
                    ad_account.stripe_subscription_id = None
                else:
                    raise e

        ad_account.stripe_subscription_id = session['subscription']
        ad_account.is_subscription_active = True
        ad_account.subscription_plan = plan_type
        ad_account.subscription_start_date = datetime.utcnow()
        ad_account.subscription_end_date = datetime.utcnow() + timedelta(days=30)

        if plan_type == 'Free Trial':
            ad_account.subscription_end_date = datetime.utcnow() + timedelta(days=5)
            start_free_trial(user)

    # Update user subscription details
    user.subscription_plan = plan_type
    user.is_subscription_active = True
    user.subscription_start_date = datetime.utcnow()
    user.subscription_end_date = datetime.utcnow() + timedelta(days=30)
    db.session.commit()

    current_app.logger.info(f"Subscription plan updated for user {user.id} and ad account {ad_account.id}")

@payment.route('/stripe-webhook', methods=['POST'])
@cross_origin(supports_credentials=True)
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = os.getenv('END_POINT_SECRET')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        current_app.logger.error(f"Stripe webhook error: {e}")
        return jsonify({'status': 'invalid payload'}), 400
    except stripe.error.SignatureVerificationError as e:
        current_app.logger.error(f"Stripe webhook signature error: {e}")
        return jsonify({'status': 'invalid signature'}), 400

    # Handle the checkout session completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        handle_checkout_session(session)

    # Handle payment failure event
    elif event['type'] == 'invoice.payment_failed':
        with current_app.test_request_context():
            cancel_subscription_route()

    return jsonify({'status': 'success'}), 200

@payment.route('/cancel-subscription', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def cancel_subscription_route():
    data = request.get_json()
    ad_account_id = data.get('ad_account_id')

    # Find the ad account by ID and verify that it belongs to the current user
    ad_account = AdAccount.query.filter_by(id=ad_account_id, user_id=current_user.id).first()

    if not ad_account:
        return jsonify({'error': 'Ad account not found or does not belong to the current user'}), 404

    try:
        # Get all active ad accounts for the current user
        active_ad_accounts = AdAccount.query.filter_by(user_id=current_user.id, is_subscription_active=True).all()

        # Check if the number of active ad accounts with running plans is less than 3
        if len(active_ad_accounts) < 3:
            # Cancel subscriptions for all ad accounts
            for account in active_ad_accounts:
                if account.stripe_subscription_id:
                    stripe.Subscription.delete(account.stripe_subscription_id)
                account.is_subscription_active = False
                account.subscription_plan = None
                account.subscription_start_date = None
                account.subscription_end_date = None
                account.stripe_subscription_id = None

            db.session.commit()
            return jsonify({'message': 'Subscription canceled for all ad accounts.'}), 200
        else:
            # Cancel the subscription for the specific ad account
            if ad_account.is_subscription_active and ad_account.stripe_subscription_id:
                stripe.Subscription.delete(ad_account.stripe_subscription_id)

            ad_account.is_subscription_active = False
            ad_account.subscription_plan = None
            ad_account.subscription_start_date = None
            ad_account.subscription_end_date = None
            ad_account.stripe_subscription_id = None
            db.session.commit()

            return jsonify({'message': 'Subscription canceled successfully for the ad account'}), 200

    except Exception as e:
        current_app.logger.error(f"Error canceling subscription: {str(e)}")
        return jsonify({'error': str(e)}), 500

@payment.route('/subscription-status/<int:ad_account_id>', methods=['GET'])
@cross_origin(supports_credentials=True)
@login_required
def subscription_status(ad_account_id):
    # Fetch the specific ad account by ID and ensure it belongs to the current user
    ad_account = AdAccount.query.filter_by(id=ad_account_id, user_id=current_user.id).first()

    if not ad_account:
        return jsonify({'error': 'Ad account not found or does not belong to the current user'}), 404

    # Check if the ad account has an active subscription
    is_active = ad_account.is_subscription_active

    # Set the plan to 'No active plan' if it's None
    plan = ad_account.subscription_plan if ad_account.subscription_plan else 'No active plan'
    
    # Format start and end dates or set to placeholder
    start_date = ad_account.subscription_start_date.strftime('%d/%m/%Y') if ad_account.subscription_start_date else '-- -- --'
    end_date = ad_account.subscription_end_date.strftime('%d/%m/%Y') if ad_account.subscription_end_date else '-- -- --'

    subscription_info = {
        'plan': plan,
        'start_date': start_date,
        'end_date': end_date,
        'is_active': is_active,
        'has_used_free_trial': current_user.has_used_free_trial  # This is still user-level info
    }
    return jsonify(subscription_info), 200


@payment.route('/start-free-trial', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def start_free_trial_route():
    data = request.get_json()
    ad_account_id = data.get('ad_account_id')
    
    current_app.logger.info(f"Received ad_account_id: {ad_account_id}")
    
    # Fetch the ad account and the corresponding user
    ad_account = AdAccount.query.filter_by(id=ad_account_id, user_id=current_user.id).first()
    
    if not ad_account:
        current_app.logger.error(f"Ad account not found or does not belong to the current user. Ad Account ID: {ad_account_id}")
        return jsonify({'error': 'Ad account not found or does not belong to the current user'}), 404
    
    user = User.query.get(current_user.id)
    
    try:
        if user.has_used_free_trial:
            current_app.logger.warning(f"User has already used Free Trial. User ID: {user.id}")
            return jsonify({'error': 'Free Trial already used, please choose a different plan'}), 400
        
        current_app.logger.info(f"Starting free trial for user ID: {user.id}")
        start_free_trial(user)  # Pass the correct User object
        
        db.session.refresh(user)  # Refresh the session with the latest data from the database
        
        # Log the updated user data
        current_app.logger.info(f"Updated User Data: has_used_free_trial={user.has_used_free_trial}, subscription_plan={user.subscription_plan}")
        
        return jsonify({'message': 'Free trial started successfully'}), 200
    except Exception as e:
        current_app.logger.error(f"Error starting free trial: {str(e)}")
        return jsonify({'error': str(e)}), 500

@payment.route('/add_ad_account', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def add_ad_account():
    try:
        # Step 1: Create the new ad account
        data = request.get_json()
        new_ad_account = AdAccount(
            user_id=current_user.id,
            ad_account_id=data.get('ad_account_id'),
            pixel_id=data.get('pixel_id'),
            facebook_page_id=data.get('facebook_page_id'),
            app_id=data.get('app_id'),
            app_secret=data.get('app_secret'),
            access_token=data.get('access_token'),
            is_bound=data.get('is_bound', False)
        )
        db.session.add(new_ad_account)
        db.session.commit()

        # Step 2: Create a Stripe checkout session
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': 'price_1Pj3pq01UFm1325dyNHzvDDX',  # Enterprise plan price ID
                'quantity': 1,
            }],
            mode='subscription',
            success_url="http://localhost:3000/pricing-section",
            cancel_url="http://localhost:3000/pricing-section",
            metadata={'user_id': current_user.id, 'ad_account_id': new_ad_account.id, 'plan_type': 'Enterprise'}
        )

        # Log the session ID to ensure it's being generated
        current_app.logger.info(f"Stripe session created with ID: {session.id}")

        # Return the session ID to the frontend
        return jsonify({'sessionId': session.id}), 200

    except Exception as e:
        current_app.logger.error(f"Error creating ad account and checkout session: {str(e)}")
        return jsonify({'error': 'Failed to create a new ad account and checkout session'}), 500

@payment.route('/user-subscription-status', methods=['GET'])
@cross_origin(supports_credentials=True)
@login_required
def user_subscription_status():
    user = current_user

    # Check if the user has an active subscription
    is_active = user.is_subscription_active

    # Set the plan to 'No active plan' if it's None
    plan = user.subscription_plan if user.subscription_plan else 'No active plan'

    subscription_info = {
        'plan': plan,
        'start_date': user.subscription_start_date,
        'end_date': user.subscription_end_date,
        'is_active': is_active,
        'has_used_free_trial': user.has_used_free_trial  # This is still user-level info
    }

    return jsonify(subscription_info), 200

@payment.route('/active-ad-accounts', methods=['GET'])
@cross_origin(supports_credentials=True)
@login_required
def active_ad_accounts():
    try:
        # Count the number of active ad accounts for the current user
        active_ad_accounts_count = AdAccount.query.filter_by(user_id=current_user.id, is_subscription_active=True).count()
        return jsonify({'count': active_ad_accounts_count}), 200
    except Exception as e:
        current_app.logger.error(f"Error fetching active ad accounts count: {str(e)}")
        return jsonify({'error': str(e)}), 500

@payment.route('/renew-subscription', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def renew_subscription_route():
    data = request.get_json()
    ad_account_id = data.get('ad_account_id')
    plan_type = data.get('plan')

    # Fetch the ad account by ID and verify that it belongs to the current user
    ad_account = AdAccount.query.filter_by(id=ad_account_id, user_id=current_user.id).first()

    if not ad_account:
        return jsonify({'error': 'Ad account not found or does not belong to the current user'}), 404

    # Determine the price ID based on the plan type
    if plan_type == 'Professional':
        price_id = 'price_1Pj3pZ01UFm1325diqAaUr32'
    elif plan_type == 'Enterprise':
        price_id = 'price_1Pj3pq01UFm1325dyNHzvDDX'
    else:
        return jsonify({'error': 'Invalid plan type'}), 400

    try:
        # Check if the ad account already has a subscription
        if ad_account.stripe_subscription_id and ad_account.is_subscription_active:
            return jsonify({'error': 'Ad account already has an active subscription'}), 400

        # Create a new Stripe checkout session
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url="http://localhost:3000/pricing-section",
            cancel_url="http://localhost:3000/pricing-section",
            metadata={
                'user_id': current_user.id, 
                'ad_account_id': ad_account.id,
                'plan_type': plan_type
            }
        )

        return jsonify({'sessionId': session.id}), 200

    except Exception as e:
        current_app.logger.error(f"Error renewing subscription: {str(e)}")
        return jsonify({'error': str(e)}), 500

@payment.route('/create-anonymous-checkout-session', methods=['POST'])
@cross_origin(supports_credentials=True)
def create_anonymous_checkout_session():
    data = request.get_json()
    plan_type = data.get('plan')

    # Define price IDs based on plan type
    if plan_type == 'Professional':
        price_id = 'price_1Pj3pZ01UFm1325diqAaUr32'
    elif plan_type == 'Enterprise':
        price_id = 'price_1Pj3pq01UFm1325dyNHzvDDX'
    elif plan_type == 'Free Trial':
        price_id = 'price_1Pj3pZ01UFm1325diqAaUr32'
    else:
        return jsonify({'error': 'Invalid plan'}), 400

    try:
        # Create session without a trial
        if plan_type != 'Free Trial':
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=f"http://localhost:5000/auth/auto-login?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url="http://localhost:3000/pricing-section",
                metadata={
                    'plan_type': plan_type,
                    'is_anonymous': True  # Add a flag to identify this as an anonymous checkout
                }
            )
        else:
            # Create session with a trial for Free Trial
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                subscription_data={'trial_period_days': 5},
                success_url=f"http://localhost:5000/auth/auto-login?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url="http://localhost:3000/pricing-section",
                metadata={
                    'plan_type': plan_type,
                    'is_anonymous': True  # Add a flag to identify this as an anonymous checkout
                }
            )
        return jsonify({'sessionId': session.id}), 200

    except Exception as e:
        current_app.logger.error(f"Stripe API error: {str(e)}")
        return jsonify({'error': str(e)}), 500

