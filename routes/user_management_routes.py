from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import User, AdAccount, db
from sqlalchemy.exc import SQLAlchemyError
from flask_cors import cross_origin
from flask_login import logout_user

# Initialize the Blueprint
user_management = Blueprint('user_management', __name__)

@user_management.route('/delete_user', methods=['DELETE', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@login_required
def delete_user():
    """
    Deletes the currently logged-in user and all associated data from the system,
    then logs the user out.
    """
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    try:
        # Use current_user to fetch the logged-in user's data
        user = User.query.get(current_user.id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Delete all associated AdAccount records
        AdAccount.query.filter_by(user_id=user.id).delete()

        # Delete the user
        db.session.delete(user)

        # Commit the changes
        db.session.commit()

        # Log out the user after deleting the account
        logout_user()

        return jsonify({"message": "User and associated data deleted successfully. You have been logged out."}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": "An error occurred while deleting the user", "details": str(e)}), 500