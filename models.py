import json
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import Text
from datetime import datetime, timedelta
from sqlalchemy import event

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
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
                
                # Update all associated ad accounts to Professional
                for account in self.ad_accounts:
                    account.subscription_plan = 'Professional Plan'
                    account.subscription_start_date = datetime.utcnow()
                    account.subscription_end_date = datetime.utcnow() + timedelta(days=30)
                    account.is_subscription_active = True
                db.session.commit()

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
    stripe_subscription_id = db.Column(db.String(255), nullable=True)  # Store Stripe subscription ID
    name = db.Column(db.String(255), nullable=False)  # Add the name field

    def get_default_config(self):
        return json.loads(self.default_config) if self.default_config else {}

    def set_default_config(self, config):
        self.default_config = json.dumps(config)

    def check_subscription_status(self):
        if self.subscription_end_date and self.subscription_end_date < datetime.utcnow():
            self.is_subscription_active = False
        return self.is_subscription_active
    
    def auto_renew_subscription(self):
        # Only renew if the subscription is active and the end date has passed
        if self.is_subscription_active and self.subscription_end_date and self.subscription_end_date < datetime.utcnow():
            # Update start and end dates to extend for another 30 days
            self.subscription_start_date = datetime.utcnow()
            self.subscription_end_date = datetime.utcnow() + timedelta(days=30)
            self.is_subscription_active = True
            db.session.commit()
            return True
        return False
    
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
