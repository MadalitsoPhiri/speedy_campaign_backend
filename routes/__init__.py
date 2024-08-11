from flask import Blueprint

# Define the blueprints
auth = Blueprint('auth', __name__)
payment = Blueprint('payment', __name__)
default_config = Blueprint('default_config', __name__)

# Import all routes from the respective route files
from .auth_routes import *  # Import all routes from auth_routes
from .payment_routes import *  # Import all routes from payment_routes
from .default_config_routes import *  # Import all routes from default_config_routes
