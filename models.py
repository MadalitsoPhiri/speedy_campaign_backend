import json
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import Text
from datetime import datetime, timedelta
from sqlalchemy import event
import stripe
import os

stripe.api_key = os.getenv('STRIPE_API_KEY')

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    stripe_customer_id = db.Column(db.String(255), unique=True, nullable=True)
    is_active = db.Column(db.Boolean, default=False)  # Set to False by default until email verification
    profile_picture = db.Column(db.String(150))
    ad_accounts = db.relationship('AdAccount', backref='user', lazy=True)
    subscription_plan = db.Column(db.String(50), nullable=True, default=None)
    subscription_start_date = db.Column(db.DateTime, nullable=True, default=None)
    subscription_end_date = db.Column(db.DateTime, nullable=True, default=None)
    is_subscription_active = db.Column(db.Boolean, default=False)
    has_used_free_trial = db.Column(db.Boolean, default=False)  # Track free trial usage
    stripe_subscription_id = db.Column(db.String(255), nullable=True)  # Store Stripe subscription ID
    reset_token_used = db.Column(db.Boolean, default=False)

    def mark_token_as_used(self):
        self.reset_token_used = True
        db.session.commit()

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def check_subscription_status(user):
        if user.subscription_end_date is None:
            return False

        if user.subscription_end_date < datetime.utcnow():
            user.is_subscription_active = False
        else:
            user.is_subscription_active = True

        return user.is_subscription_active
    
    def upgrade_free_trial_to_pro(self):
        if self.subscription_plan == 'Free Trial' and self.is_subscription_active:
            if self.subscription_end_date and datetime.utcnow() >= self.subscription_end_date:
                # Upgrade to Professional Plan
                renew_subscription(self, 'Professional')
                
class AdAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ad_account_id = db.Column(db.String(255), nullable=True)
    pixel_id = db.Column(db.String(255), nullable=True)
    facebook_page_id = db.Column(db.String(255), nullable=True)
    app_id = db.Column(db.String(255), nullable=True)
    app_secret = db.Column(db.String(255), nullable=True)
    access_token = db.Column(db.String(255), nullable=True)
    is_bound = db.Column(db.Boolean, default=False)
    default_config = db.Column(Text, nullable=True)  # Store configuration as JSON string
    subscription_plan = db.Column(db.String(50), default=None)
    subscription_start_date = db.Column(db.DateTime, nullable=True, default=None)
    subscription_end_date = db.Column(db.DateTime, nullable=True, default=None)
    is_subscription_active = db.Column(db.Boolean, default=False)
    stripe_subscription_id = db.Column(db.String(255), unique=True, nullable=True)  # Enforce uniqueness
    name = db.Column(db.String(255), nullable=False)  # Add the name field
    business_manager_id = db.Column(db.String(255), nullable=True)  # Add the BM ID field

    def get_default_config(self):
        return json.loads(self.default_config) if self.default_config else {}

    def set_default_config(self, config):
        self.default_config = json.dumps(config)

    def check_subscription_status(self):
        if self.subscription_end_date and self.subscription_end_date < datetime.utcnow():
            self.is_subscription_active = False
        return self.is_subscription_active
    
    
    def auto_renew_subscription(self):
        if self.stripe_subscription_id:
            try:
                # Retrieve subscription details from Stripe
                stripe_subscription = stripe.Subscription.retrieve(self.stripe_subscription_id)

                if stripe_subscription['status'] != 'active':
                    # If the subscription is inactive, cancel it locally
                    print(f"❌ Stripe subscription {self.stripe_subscription_id} is not active. Cancelling locally.")
                    self.cancel_subscription()
                    return False

                # Extract subscription start and end dates from Stripe (UNIX timestamps)
                start_timestamp = stripe_subscription.get("current_period_start")
                end_timestamp = stripe_subscription.get("current_period_end")

                if not start_timestamp or not end_timestamp:
                    print(f"⚠️ Unable to retrieve start/end dates from Stripe for {self.stripe_subscription_id}")
                    return False  # Exit if we cannot retrieve dates

                # Convert UNIX timestamps to datetime
                new_start_date = datetime.utcfromtimestamp(start_timestamp)
                new_end_date = datetime.utcfromtimestamp(end_timestamp)

                # Update the database with the new dates from Stripe
                self.subscription_start_date = new_start_date
                self.subscription_end_date = new_end_date
                self.is_subscription_active = True  # Ensure status is updated
                db.session.commit()

                print(f"✅ Subscription {self.stripe_subscription_id} auto-renewed successfully.")
                return True

            except stripe.error.InvalidRequestError as e:
                print(f"❌ Stripe subscription {self.stripe_subscription_id} not found: {e}. Cancelling locally.")
                self.cancel_subscription()
            except stripe.error.APIConnectionError as e:
                print(f"🔌 Network error when connecting to Stripe: {e}")
            except stripe.error.StripeError as e:
                print(f"⚠️ Stripe API error: {e}")
            except Exception as e:
                print(f"❗ Unexpected error in auto-renewal: {e}")

        return False  # Return False if renewal was not possible

    def cancel_subscription(self):
        """Marks the subscription as canceled in the local database"""
        print(f"🚫 Canceling local subscription for {self.stripe_subscription_id}")
        self.is_subscription_active = False
        self.subscription_plan = None
        self.subscription_start_date = None
        self.subscription_end_date = None
        self.stripe_subscription_id = None
        db.session.commit()

    
# Event listener for setting the name before inserting
@event.listens_for(AdAccount, 'before_insert')
def set_ad_account_name(mapper, connect, target):
    ad_account_count = AdAccount.query.filter_by(user_id=target.user_id).count()
    target.name = f"Ad Account {ad_account_count + 1}"

def start_free_trial(user):
    if user.has_used_free_trial:
        raise ValueError("Free Trial has already been used.")
    
    user.subscription_plan = 'Free Trial'
    user.subscription_start_date = datetime.utcnow()
    user.subscription_end_date = datetime.utcnow() + timedelta(days=5)
    user.is_subscription_active = True
    user.has_used_free_trial = True  # Mark that the user has used the free trial
    db.session.commit()


def renew_subscription(user, plan):
    if plan == 'Professional':
        user.subscription_plan = 'Professional Plan'
        user.subscription_start_date = datetime.utcnow()
        user.subscription_end_date = datetime.utcnow() + timedelta(days=30)
    elif plan == 'Enterprise':
        user.subscription_plan = 'Enterprise Plan'
        user.subscription_start_date = datetime.utcnow()
        user.subscription_end_date = datetime.utcnow() + timedelta(days=30)
    user.is_subscription_active = True
    db.session.commit()

def cancel_subscription(user):
    try:
        user.is_subscription_active = False
        user.subscription_plan = None  # Set plan to None
        user.subscription_start_date = None  # Clear start date
        user.subscription_end_date = None  # Clear end date
        db.session.commit()
    except Exception as e:
        print(f"Error in cancel_subscription: {str(e)}")
        raise


def check_subscription_status(user):
    if user.subscription_end_date < datetime.utcnow():
        user.is_subscription_active = False
    return user.is_subscription_active
