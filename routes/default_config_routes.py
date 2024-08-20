from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from flask_cors import cross_origin
from models import AdAccount, db
import requests

default_config = Blueprint('default_config', __name__)

# Endpoint to exchange short-lived token for long-lived token and store it in the database
@default_config.route('/ad_account/<int:id>/exchange-token', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def exchange_token(id):
    data = request.get_json()
    short_lived_token = data.get('access_token')
    app_id = '1153977715716035'  # Hardcoded App ID
    app_secret = '30d73e973e26535fc1e445f2e0b16cb7'  # Hardcoded App Secret

    if not short_lived_token:
        return jsonify({'message': 'Access token is required'}), 400

    ad_account = AdAccount.query.get(id)

    if not ad_account or ad_account.user_id != current_user.id:
        return jsonify({'message': 'Ad account not found or access denied'}), 404

    try:
        response = requests.get(
            'https://graph.facebook.com/v16.0/oauth/access_token',
            params={
                'grant_type': 'fb_exchange_token',
                'client_id': app_id,
                'client_secret': app_secret,
                'fb_exchange_token': short_lived_token
            }
        )
        
        response_data = response.json()
        
        if 'access_token' in response_data:
            long_lived_token = response_data['access_token']
            
            # Save the long-lived token, App ID, and App Secret to the ad account
            ad_account.access_token = long_lived_token
            ad_account.app_id = app_id
            ad_account.app_secret = app_secret
            
            db.session.commit()
            
            return jsonify({'message': 'Long-lived token and credentials stored successfully', 'long_lived_token': long_lived_token}), 200
        else:
            return jsonify({'message': 'Failed to exchange token', 'error': response_data}), 400
    
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Existing endpoints
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
