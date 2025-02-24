from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import User, AdAccount, db
from sqlalchemy.exc import SQLAlchemyError
from flask_cors import cross_origin
from flask_login import logout_user
import stripe
import os

# Initialize the Blueprint
user_management = Blueprint('user_management', __name__)

stripe.verify_ssl_certs = True

# Initialize Stripe with your secret key
stripe.api_key = os.getenv('STRIPE_API_KEY')

from stripe.error import InvalidRequestError

@user_management.route('/delete_user', methods=['DELETE', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@login_required
def delete_user():
    """
    Deletes the currently logged-in user, including all associated ad accounts and subscriptions,
    then logs the user out.
    """
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    try:
        # Get the logged-in user
        user = User.query.get(current_user.id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Fetch all ad accounts associated with the user
        ad_accounts = AdAccount.query.filter_by(user_id=user.id).all()

        for ad_account in ad_accounts:
            if ad_account.stripe_subscription_id:
                try:
                    stripe.Subscription.delete(ad_account.stripe_subscription_id)

                except InvalidRequestError as e:
                    if "No such subscription" in str(e):
                        print(f"⚠️ No such subscription found for {ad_account.ad_account_id}, skipping...")
                    else:
                        return jsonify({"error": "Stripe error", "details": str(e)}), 500

                except stripe.error.StripeError as e:
                    return jsonify({"error": "Stripe API error", "details": str(e)}), 500

        try:
            # Delete all associated AdAccount records
            AdAccount.query.filter_by(user_id=user.id).delete()

            # Delete the user
            db.session.delete(user)

            # Commit the changes
            db.session.commit()

            # Log out the user after deleting the account
            logout_user()

            return jsonify({"message": "User and all associated data deleted successfully. You have been logged out."}), 200

        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({"error": "Database error while deleting the user", "details": str(e)}), 500

    except Exception as e:
        return jsonify({"error": "Unexpected error occurred", "details": str(e)}), 500
