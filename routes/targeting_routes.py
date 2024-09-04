from flask import Blueprint, request, jsonify
from flask_login import login_required
from flask_cors import cross_origin
from facebook_business.api import FacebookAdsApi
from facebook_business.adobjects.adaccount import AdAccount
from facebook_business.adobjects.customaudience import CustomAudience
from facebook_business.exceptions import FacebookRequestError
from facebook_business.adobjects.targetingsearch import TargetingSearch
import logging
from .audiences.audiences import (
    custom_audience_create,
    read_single_audience,
    read_all_audiences,
    custom_audience_update,
    custom_audience_delete,
    custom_audience_fields  # Importing the custom audience fields
)

targeting = Blueprint('targeting', __name__)

# Ensure logger is set up for debugging
logging.basicConfig(level=logging.DEBUG)

# Route to fetch custom audiences
@targeting.route('/custom_audiences', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def read_all_audiences():
    data = request.json
    app_id = data.get('app_id')
    app_secret = data.get('app_secret')
    access_token = data.get('access_token')
    ad_account_id = data.get('ad_account_id')

    if not app_id or not app_secret or not access_token or not ad_account_id:
        logging.error("Missing required parameters: app_id, app_secret, access_token, or ad_account_id")
        return jsonify({'error': 'Missing required parameters: app_id, app_secret, access_token, or ad_account_id'}), 400

    try:
        # Initialize the Facebook Ads API
        FacebookAdsApi.init(app_id, app_secret, access_token, api_version='v20.0')

        # Fetch custom audiences for the ad account
        ad_account = AdAccount(ad_account_id)
        audiences = ad_account.get_custom_audiences(fields=custom_audience_fields)

        # Prepare the response list
        audience_list = []
        for audience in audiences:
            audience_list.append({
                'id': audience.get('id'),
                'name': audience.get('name'),
                'approximate_count': audience.get('approximate_count', 'N/A')  # Handle missing field
            })

        return jsonify(audience_list), 200

    except FacebookRequestError as fb_error:
        # Handle specific Facebook errors
        error_message = {
            "message": fb_error.api_error_message(),
            "status": fb_error.http_status(),
            "type": fb_error.api_error_type()
        }
        logging.error(f"FacebookRequestError: {error_message}")
        return jsonify({'error': error_message}), 500

    except Exception as e:
        logging.error(f"Error fetching custom audiences: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Fetch countries using TargetingSearch API
@targeting.route('/get_countries', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def fetch_countries():
    logging.debug("Received request for countries")
    
    data = request.json
    query = data.get('query', {})
    app_id = data.get('app_id')
    app_secret = data.get('app_secret')
    access_token = data.get('access_token')

    if not app_id or not app_secret or not access_token:
        logging.error("Missing required parameters")
        return jsonify({'error': 'Missing required parameters'}), 400

    if not isinstance(query, dict):
        logging.error("Invalid query format")
        return jsonify({'error': 'Invalid query format'}), 400

    try:
        FacebookAdsApi.init(app_id, app_secret, access_token, api_version='v19.0')
        
        params = {
            'type': 'adgeolocation',
            'location_types': ['country'],
            'q': query.get('q', ''),
            'limit': query.get('limit', 1000)
        }

        search_result = TargetingSearch.search(params=params)
        
        # Convert the TargetingSearch objects to JSON-serializable dictionaries
        serialized_results = []
        for result in search_result:
            serialized_results.append({
                'country_code': result.get('country_code'),
                'key': result.get('key'),
                'name': result.get('name'),
                'supports_city': result.get('supports_city'),
                'supports_region': result.get('supports_region'),
                'type': result.get('type')
            })
        
        logging.debug(f"Fetched countries: {serialized_results}")
        return jsonify(serialized_results), 200

    except FacebookRequestError as fb_error:
        error_message = {
            "message": fb_error.api_error_message(),
            "status": fb_error.http_status(),
            "type": fb_error.api_error_type()
        }
        logging.error(f"FacebookRequestError occurred: {error_message}")
        return jsonify({'error': error_message}), 500
    
    except Exception as e:
        logging.error(f"Exception occurred: {str(e)}")
        return jsonify({'error': str(e)}), 500

@targeting.route('/interests', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def get_audience_interests():
    ad_account_id = request.json.get('ad_account_id', '')
    access_token = request.json.get('access_token', '')
    app_id = request.json.get('app_id', '')
    app_secret = request.json.get('app_secret', '')
    query = request.json.get('query', {})

    # Validate the presence of required fields
    if not ad_account_id or not access_token or not app_id or not app_secret:
        logging.error("Missing required parameters: ad_account_id, access_token, app_id, or app_secret")
        return jsonify({'error': 'Missing required parameters'}), 400

    # Validate the 'q' parameter in the query
    q_value = query.get('q', '').strip()
    if not q_value:
        logging.error("The 'q' parameter is required for the ad interest search")
        return jsonify({'error': "The 'q' parameter is required"}), 400

    try:
        # Initialize the Facebook API with the given credentials
        FacebookAdsApi.init(app_id, app_secret, access_token, api_version='v20.0')

        # Prepare parameters for the targeting search
        params = {
            'type': query.get('type', 'adinterest'),
            'q': q_value,  # Ensure 'q' is passed
            'limit': query.get('limit', 1000),
            'access_token': access_token,
        }

        # Perform the targeting search
        search_result = TargetingSearch.search(params=params)

        # Serialize the search results
        serialized_results = [
            {
                'audience_size_lower_bound': result.get('audience_size_lower_bound'),
                'audience_size_upper_bound': result.get('audience_size_upper_bound'),
                'id': result.get('id'),
                'name': result.get('name'),
                'path': result.get('path'),
                'topic': result.get('topic'),
            }
            for result in search_result
        ]

        return jsonify(serialized_results), 200

    except FacebookRequestError as fb_error:
        # Handle errors from the Facebook API
        error_message = {
            "message": fb_error.api_error_message(),
            "status": fb_error.http_status(),
            "type": fb_error.api_error_type(),
        }
        logging.error(f"FacebookRequestError: {error_message}")
        return jsonify({'error': error_message}), 500

    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
        return jsonify({'error': str(e)}), 500
