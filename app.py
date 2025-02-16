from flask import Flask
# from flask_migrate import Migrate
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_cors import CORS
from datetime import timedelta
from config import Config
from models import db, User, AdAccount
from routes import auth, payment, default_config, targeting, user_management  # Import your new routes here
import os
from apscheduler.schedulers.background import BackgroundScheduler
import atexit


REACT_APP_API_URL=os.getenv('REACT_APP_API_URL')

app = Flask(__name__, instance_relative_config=True, static_folder='static')
app.config.from_object(Config)
app.config.from_pyfile('config.py', silent=True)

# Ensure the upload directory exists
UPLOAD_FOLDER = 'static/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Enable CORS with credentials
cors = CORS(app, supports_credentials=True, resources={r"/*": {"origins": REACT_APP_API_URL}})

# Initialize Flask extensions
db.init_app(app)
# migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'

# Set the remember cookie duration
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Register the Blueprints
app.register_blueprint(auth, url_prefix='/auth')
app.register_blueprint(payment, url_prefix='/payment')
app.register_blueprint(default_config, url_prefix='/config')  # Register new routes with a prefix
app.register_blueprint(targeting, url_prefix='/targeting')
app.register_blueprint(user_management, url_prefix='/user_management')


def check_and_renew_subscriptions():
    with app.app_context():
        # Get all active users
        users = User.query.all()

        for user in users:
            # Get all active ad accounts for this user
            active_ad_accounts = AdAccount.query.filter_by(user_id=user.id, is_subscription_active=True).all()

            if not active_ad_accounts:
                # If no active ad accounts exist, set user subscription to inactive
                user.is_subscription_active = False
                db.session.commit()
                print(f"User {user.id} has no active ad accounts. Setting is_subscription_active=False.")
            else:
                # Ensure the user is marked as active if they have active ad accounts
                user.is_subscription_active = True
                db.session.commit()
                print(f"User {user.id} has active ad accounts. Keeping is_subscription_active=True.")

            # Attempt to auto-renew subscriptions for each active ad account
            for account in active_ad_accounts:
                account.auto_renew_subscription()

# Function to upgrade free trials to Professional Plan after 5 days
def upgrade_free_trials():
    with app.app_context():
        # Get all users on a free trial
        users_on_free_trial = User.query.filter_by(subscription_plan='Free Trial', is_subscription_active=True).all()
        
        for user in users_on_free_trial:
            user.upgrade_free_trial_to_pro()

# Initialize the APScheduler and schedule the job
scheduler = BackgroundScheduler()
scheduler.add_job(func=check_and_renew_subscriptions, trigger="interval", days=1)
scheduler.add_job(func=upgrade_free_trials, trigger="interval", days=1)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    create_tables()
    app.run(host='0.0.0.0', port=5000, debug=True)
