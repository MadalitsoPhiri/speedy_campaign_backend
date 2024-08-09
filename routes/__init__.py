from flask import Blueprint

auth = Blueprint('auth', __name__)
payment = Blueprint('payment', __name__)

from .auth_routes import *  # Import all routes from auth_routes
from .payment_routes import *  # Import all routes from paymentroutes
