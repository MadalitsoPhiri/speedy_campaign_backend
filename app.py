from flask import Flask
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_cors import CORS
from datetime import timedelta
from config import Config
from models import db, User
from routes import auth, payment
import os

app = Flask(__name__, instance_relative_config=True, static_folder='static')
app.config.from_object(Config)
app.config.from_pyfile('config.py', silent=True)

# Ensure the upload directory exists
UPLOAD_FOLDER = 'static/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Enable CORS with credentials
cors = CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:3000"}})

# Initialize Flask extensions
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'

# Set the remember cookie duration
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app.register_blueprint(auth, url_prefix='/auth')  # Register auth Blueprint with a prefix
app.register_blueprint(payment, url_prefix = '/payment')  # Register payment Blueprint without a prefix

def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)