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
import uuid

# Initialize the Blueprint for payment routes
payment = Blueprint('payment', __name__)

load_dotenv()

stripe.verify_ssl_certs = True

# Initialize Stripe with your secret key
stripe.api_key = os.getenv('STRIPE_API_KEY')

REACT_APP_API_URL=os.getenv('REACT_APP_API_URL')
BACKEND_API_URL=os.getenv('BACKEND_API_URL')
STRIPE_PROFESSIONAL_PLAN_ID=os.getenv('STRIPE_PROFESSIONAL_PLAN_ID')
STRIPE_ENTERPRISE_PLAN_ID=os.getenv('STRIPE_ENTERPRISE_PLAN_ID')
STRIPE_TEST_PLAN_ID=os.getenv('STRIPE_TEST_PLAN_ID')

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
    chosen_ad_account_id = data.get('chosen_ad_account_id')
    user = User.query.get(current_user.id)


    current_app.logger.info(f"Plan Type: {plan_type}, Ad Account ID: {ad_account_id}")

    ad_account = AdAccount.query.filter_by(id=ad_account_id, user_id=current_user.id).first()

    if not ad_account:
        current_app.logger.error(f"Ad account not found or does not belong to the current user. Ad Account ID: {ad_account_id}")
        return jsonify({'error': 'Ad account not found or does not belong to the current user'}), 404

    if plan_type == 'Professional':
        price_id = STRIPE_PROFESSIONAL_PLAN_ID
    elif plan_type == 'Enterprise':
        price_id = STRIPE_ENTERPRISE_PLAN_ID
    elif plan_type == 'Free Trial':
        if current_user.has_used_free_trial:
            current_app.logger.warning(f"User has already used the Free Trial. User ID: {current_user.id}")
            return jsonify({'error': 'Free Trial already used, please choose a different plan'}), 400
        price_id = STRIPE_PROFESSIONAL_PLAN_ID
    else:
        current_app.logger.error(f"Invalid plan type received: {plan_type}")
        return jsonify({'error': 'Invalid plan'}), 400

    current_app.logger.info(f"Price ID set to: {price_id}")

    try:
        # Create session without a trial
        if plan_type != 'Free Trial':
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                customer_email=user.email,

                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=f"{REACT_APP_API_URL}/success",
                cancel_url=f"{REACT_APP_API_URL}/pricing-section",
                metadata={
                    'user_id': current_user.id, 
                    'ad_account_id': ad_account.id,
                    'chosen_ad_account_id': str(chosen_ad_account_id),
                    'plan_type': plan_type,
                    'is_anonymous': False
                }
            )
        else:
            # Create session with a trial for Free Trial
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                customer_email=user.email,
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                subscription_data={'trial_period_days': 1},
                success_url=f"{REACT_APP_API_URL}/success",
                cancel_url=f"{REACT_APP_API_URL}/pricing-section",
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
    is_anonymous = session['metadata']['is_anonymous'] == 'True'
    commit_needed = True  # Flag to control whether to commit changes

    if is_anonymous:
        session_id = session.get('id')

        if not session_id:
            session_id = str(uuid.uuid4())  # Fallback unique identifier
            current_app.logger.warning(f"⚠️ No session ID found! Using fallback UUID: {session_id}")

        email = f"anon_{session_id}@quickcampaigns.io"
        name = session.get('customer_details', {}).get('name', "Anonymous User")

        # Generate a random password
        random_password = generate_random_password()
        hashed_password = generate_password_hash(random_password, method='pbkdf2:sha256')

        # Create a new user account with hashed password
        user = User(email=email, username=name, password=hashed_password, is_active=True)
        user.subscription_plan = plan_type
        user.has_used_free_trial = True
        db.session.add(user)
        user.stripe_customer_id = session['customer']
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
            commit_needed = False  # Skip commit for free trial
            try:
                start_free_trial(user, ad_account, session)
            except ValueError as e:
                current_app.logger.warning(f"Cannot start free trial: {e}")

    else:  
        try:
            metadata = session.get('metadata', {})
            action = metadata.get('action')
            new_ad_account = None  # Initialize to None

            if action == 'add_ad_account':
                new_ad_account = AdAccount(
                    user_id=metadata['user_id'],
                    is_bound=metadata.get('is_bound', 'false').lower() == 'true'
                )
                db.session.add(new_ad_account)
                db.session.commit()
            else:
                current_app.logger.info(f"Checkout session completed for action: {action}")

        except Exception as e:
            current_app.logger.error(f"Error handling checkout session: {str(e)}") 

        # Normal checkout handling for logged-in users
        user_id = session['metadata']['user_id']
        if new_ad_account:
            ad_account_id = new_ad_account.id
            print(ad_account_id)
        else:
            ad_account_id = session['metadata']['ad_account_id']     

        user = User.query.get(user_id)
        ad_account = AdAccount.query.get(ad_account_id)

        if user and ad_account:
            handle_normal_checkout(user, session, plan_type, ad_account_id)
            user.has_used_free_trial = True
            pass

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

def handle_normal_checkout(user, session, plan_type, ad_account_id):
    ad_account = AdAccount.query.get(ad_account_id)
    commit_needed = True

    if ad_account.subscription_plan == 'Free Trial' and plan_type in ['Professional', 'Enterprise']:
        current_app.logger.info(f"Ad Account {ad_account.id} is upgrading from Free Trial to {plan_type}. Cancelling Free Trial subscription in Stripe.")

        if ad_account.stripe_subscription_id:
            try:
                stripe.Subscription.delete(ad_account.stripe_subscription_id)
                current_app.logger.info(f"Successfully canceled Free Trial subscription for Ad Account {ad_account.id} (User {user.id}).")
            except stripe.error.InvalidRequestError as e:
                if "No such subscription" in str(e):
                    current_app.logger.warning(f"Free Trial subscription {ad_account.stripe_subscription_id} not found in Stripe. Proceeding.")
                else:
                    raise e  # Re-raise unexpected Stripe errors
    
    elif plan_type == 'Free Trial':
        commit_needed = False  # Skip commit for free trial
        try:
            start_free_trial(user, ad_account, session)
        except ValueError as e:
            current_app.logger.warning(f"Cannot start free trial: {e}")

    else:
        ad_account.stripe_subscription_id = session['subscription']
        ad_account.is_subscription_active = True
        ad_account.subscription_plan = plan_type
        ad_account.subscription_start_date = datetime.utcnow()
        ad_account.subscription_end_date = datetime.utcnow() + timedelta(days=30)
    
    # Update user subscription details only if not Free Trial
    if commit_needed:
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
        # Log the failure without custom subscription cancellation
        subscription_id = event['data']['object']['subscription']
        current_app.logger.warning(f"Payment failed for subscription {subscription_id}")
        # print('failed')
        # with current_app.test_request_context():
        #     cancel_subscription_route()

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
                    try:
                        stripe.Subscription.modify(
                            account.stripe_subscription_id,
                            cancel_at_period_end=True  # Subscription stays active until the end of the period
                        )

                    except stripe.error.InvalidRequestError as e:
                        if "No such subscription" in str(e):
                            current_app.logger.warning(f"Stripe subscription {account.stripe_subscription_id} not found. Proceeding.")
                        else:
                            raise e  # Re-raise other Stripe errors

            return jsonify({'message': 'Subscription canceled for all ad accounts.'}), 200
        else:
            # Cancel the subscription for the specific ad account
            if ad_account.is_subscription_active and ad_account.stripe_subscription_id:
                try:
                    stripe.Subscription.modify(
                            ad_account.stripe_subscription_id,
                            cancel_at_period_end=True  # Subscription stays active until the end of the period
                        )
                except stripe.error.InvalidRequestError as e:
                    if "No such subscription" in str(e):
                        current_app.logger.warning(f"Stripe subscription {ad_account.stripe_subscription_id} not found. Proceeding.")
                    else:
                        raise e  # Re-raise other Stripe errors

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


@payment.route('/add_ad_account', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def add_ad_account():
    user = User.query.get(current_user.id)
    try:

        # Create a Stripe checkout session
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            customer_email=user.email,
            line_items=[{
                'price': STRIPE_ENTERPRISE_PLAN_ID,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=f"{REACT_APP_API_URL}/success",
            cancel_url=f"{REACT_APP_API_URL}/pricing-section",
            metadata={
                'user_id': current_user.id,
                'action': 'add_ad_account',  # Add specific action metadata
                'plan_type': 'Enterprise',
                'is_anonymous': False
            }
        )

        # Log the session ID
        current_app.logger.info(f"Stripe session created with ID: {session.id}")

        # Return the session ID to the frontend
        return jsonify({'sessionId': session.id}), 200

    except Exception as e:
        current_app.logger.error(f"Error creating Stripe checkout session: {str(e)}")
        return jsonify({'error': 'Failed to create checkout session'}), 500

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
    
    # Debug: Log received data
    current_app.logger.info(f"Received renewal request: {data}")
    user = User.query.get(current_user.id)

    ad_account_id = data.get('ad_account_id')
    plan_type = data.get('plan')

    # Debug: Ensure ad_account_id and plan_type exist
    if not ad_account_id:
        current_app.logger.error("Missing ad_account_id in request")
        return jsonify({'error': 'Missing ad_account_id'}), 400

    if not plan_type:
        current_app.logger.error("Missing plan_type in request")
        return jsonify({'error': 'Missing plan_type'}), 400

    # Fetch the ad account by ID and verify that it belongs to the current user
    ad_account = AdAccount.query.filter_by(id=ad_account_id, user_id=current_user.id).first()

    if not ad_account:
        current_app.logger.error(f"Ad account {ad_account_id} not found for user {current_user.id}")
        return jsonify({'error': 'Ad account not found or does not belong to the current user'}), 404

    # Debug: Log found ad account
    current_app.logger.info(f"Found ad account: {ad_account.id}, Plan: {ad_account.subscription_plan}")

    # Determine the price ID based on the plan type
    if plan_type == 'Professional':
        price_id = STRIPE_PROFESSIONAL_PLAN_ID
    elif plan_type == 'Enterprise':
        price_id = STRIPE_ENTERPRISE_PLAN_ID
    elif plan_type == 'Free Trial':
        price_id = STRIPE_PROFESSIONAL_PLAN_ID
        plan_type = "Professional"
    else:
        current_app.logger.error(f"Invalid plan type received: {plan_type}")
        return jsonify({'error': 'Invalid plan type'}), 400

    # Debug: Log final plan and price ID
    current_app.logger.info(f"Final Plan Type: {plan_type}, Price ID: {price_id}")

    try:
        # Create a new Stripe checkout session
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            customer_email=user.email,
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=f"{REACT_APP_API_URL}/success",
            cancel_url=f"{REACT_APP_API_URL}/pricing-section",
            metadata={
                'user_id': current_user.id, 
                'ad_account_id': ad_account.id,
                'plan_type': plan_type,
                'is_anonymous': False
            }
        )

        # Debug: Log Stripe session creation
        current_app.logger.info(f"Stripe checkout session created successfully. Session ID: {session.id}")

        return jsonify({'sessionId': session.id}), 200

    except stripe.error.StripeError as e:
        current_app.logger.error(f"Stripe API error: {str(e)}")
        return jsonify({'error': f"Stripe error: {str(e)}"}), 500

    except Exception as e:
        current_app.logger.error(f"Unexpected error renewing subscription: {str(e)}")
        return jsonify({'error': str(e)}), 500

@payment.route('/create-anonymous-checkout-session', methods=['POST'])
@cross_origin(supports_credentials=True)
def create_anonymous_checkout_session():
    data = request.get_json()
    plan_type = data.get('plan')

    # Define price IDs based on plan type
    if plan_type == 'Professional':
        price_id = STRIPE_PROFESSIONAL_PLAN_ID
    elif plan_type == 'Enterprise':
        price_id = STRIPE_ENTERPRISE_PLAN_ID
    elif plan_type == 'Free Trial':
        price_id = STRIPE_PROFESSIONAL_PLAN_ID
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
                success_url=f"{REACT_APP_API_URL}/registration?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{REACT_APP_API_URL}/pricing-section",
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
                subscription_data={'trial_period_days': 1},
                success_url=f"{REACT_APP_API_URL}/registration?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{REACT_APP_API_URL}/pricing-section",
                metadata={
                    'plan_type': plan_type,
                    'is_anonymous': True  # Add a flag to identify this as an anonymous checkout
                }
            )
        return jsonify({'sessionId': session.id}), 200

    except Exception as e:
        current_app.logger.error(f"Stripe API error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@payment.route('/get-checkout-session', methods=['GET'])
def get_checkout_session():
    session_id = request.args.get('session_id')
    
    try:
        session = stripe.checkout.Session.retrieve(session_id)
        customer_email = session.get('customer_details', {}).get('email', '')
        customer_name = session.get('customer_details', {}).get('name', '')

        if not customer_email or not customer_name:
            return jsonify({'error': 'No customer details found'}), 400

        return jsonify({'email': customer_email, 'name': customer_name})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@payment.route('/check-ad-account-cancel-status/<int:ad_account_id>', methods=['GET'])
@cross_origin(supports_credentials=True)
@login_required
def check_ad_account_cancel_status(ad_account_id):
    # Fetch the ad account from the database
    ad_account = AdAccount.query.filter_by(id=ad_account_id, user_id=current_user.id).first()

    if not ad_account:
        return jsonify({"error": "Ad account not found or does not belong to the current user"}), 404

    # Ensure the ad account has a Stripe subscription ID
    if not ad_account.stripe_subscription_id:
        return jsonify({"cancel_at_period_end": False}), 200  # No subscription = False

    try:
        # Retrieve the subscription from Stripe
        stripe_subscription = stripe.Subscription.retrieve(ad_account.stripe_subscription_id)

        # Check the cancel_at_period_end flag
        cancel_at_period_end = stripe_subscription.get("cancel_at_period_end", False)

        return jsonify({"cancel_at_period_end": cancel_at_period_end}), 200

    except stripe.error.InvalidRequestError as e:
        current_app.logger.error(f"Stripe error: {str(e)}")
        return jsonify({"cancel_at_period_end": False}), 200  # If invalid, treat as not canceled

    except Exception as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

@payment.route('/create-billing-portal-session', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def create_billing_portal_session():
    try:
        # Ensure the user has a Stripe customer ID
        user = User.query.get(current_user.id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not user.stripe_customer_id:
            return jsonify({'error': 'no_subscription'}), 400  # Return this for frontend alert

        # Create a Stripe Billing Portal session
        session = stripe.billing_portal.Session.create(
            customer=user.stripe_customer_id,  # User's Stripe Customer ID
            return_url=f"{REACT_APP_API_URL}/profile-management"  # Redirect after session
        )

        return jsonify({'url': session.url}), 200  # Return the portal URL

    except stripe.error.StripeError as e:
        current_app.logger.error(f"Stripe API error: {str(e)}")
        return jsonify({'error': 'Failed to create billing portal session'}), 500
