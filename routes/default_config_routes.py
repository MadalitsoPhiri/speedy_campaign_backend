from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import AdAccount, db

default_config = Blueprint('default_config', __name__)

@default_config.route('/ad_account/<int:id>/config', methods=['POST'])
@login_required
def update_ad_account_config(id):
    data = request.get_json()
    ad_account = AdAccount.query.get(id)
    
    if not ad_account or ad_account.user_id != current_user.id:
        return jsonify({'message': 'Ad account not found or access denied'}), 404

    try:
        ad_account.set_default_config(data)
        db.session.commit()
        return jsonify({'message': 'Ad account configuration updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@default_config.route('/ad_account/<int:id>/config', methods=['GET'])
@login_required
def get_ad_account_config(id):
    ad_account = AdAccount.query.get(id)
    
    if not ad_account or ad_account.user_id != current_user.id:
        return jsonify({'message': 'Ad account not found or access denied'}), 404

    config = ad_account.get_default_config()
    return jsonify(config), 200
