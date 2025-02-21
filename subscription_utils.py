from datetime import datetime, timedelta
from models import db

def start_free_trial(user, ad_account, session):
    if user.has_used_free_trial:
        raise ValueError("Free Trial has already been used.")
        
    ad_account.stripe_subscription_id = session['subscription']
    ad_account.is_subscription_active = True
    ad_account.is_active_manual = True
    ad_account.subscription_plan = "Free Trial"
    ad_account.subscription_start_date = datetime.utcnow()
    ad_account.subscription_end_date = datetime.utcnow() + timedelta(days=1)

    user.subscription_plan = 'Free Trial'
    user.subscription_start_date = datetime.utcnow()
    user.subscription_end_date = datetime.utcnow() + timedelta(days=1)
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
    user.is_subscription_active = False
    user.subscription_plan = None  # Set to None or a string indicating no active plan
    user.subscription_end_date = datetime.utcnow()
    db.session.commit()

def check_subscription_status(user):
    if user.subscription_end_date < datetime.utcnow():
        user.is_subscription_active = False
    return user.is_subscription_active

def update_running_plan(user):
    active_subscriptions = [account for account in user.ad_accounts if account.is_subscription_active]
    if not active_subscriptions:
        user.subscription_plan = None
    elif len(active_subscriptions) > 0:
        user.subscription_plan = 'Enterprise'
    db.session.commit()
