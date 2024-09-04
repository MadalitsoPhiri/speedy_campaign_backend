from flask import Flask, request, jsonify, current_app
from facebook_business.api import FacebookAdsApi
from facebook_business.adobjects.adaccount import AdAccount
from facebook_business.adobjects.customaudience import CustomAudience
from facebook_business.exceptions import FacebookRequestError
import requests
import logging


custom_audience_fields = [
    'id',
    'account_id',
    'approximate_count_lower_bound',
    'approximate_count_upper_bound',
    'customer_file_source',
    'data_source',
    'delivery_status',
    'description',
    # 'external_event_source',
    # 'is_value_based',
    'lookalike_audience_ids',
    'lookalike_spec',
    'name',
    'operation_status',
    'opt_out_link',
    'page_deletion_marked_delete_time',
    'permission_for_actions',
    'pixel_id',
    'retention_days',
    'rule',
    'rule_aggregation',
    'sharing_status',
    'subtype',
    'time_content_updated',
    'time_created',
    'time_updated'
]

def setup_common_params(name, description, audience_type, access_token):
    return {
        'name': name,
        'subtype': audience_type,
        'description': description,
        'access_token': access_token
    }

def custom_audience_create(app_id, app_secret, access_token, ad_account_id, req_params):
    try:
        FacebookAdsApi.init(app_id, app_secret, access_token, api_version='v20.0')

        params = {key: value for key, value in {
            'name': req_params.get('name'),
            'description': req_params.get('description'),
            'subtype': req_params.get('subtype'),
            'customer_file_source': req_params.get('customer_file_source'),
        }.items() if value is not None and value != ""}
        
        # Create the custom audience
        audience = AdAccount(ad_account_id).create_custom_audience(fields=custom_audience_fields, params=params)
        
        # Serialize the CustomAudience object to a dictionary
        audience_data = {
            'account_id': audience['account_id'],
            'id': audience['id'],
            'name': audience['name'],
            'description': audience.get('description', ''),
        }
        
        current_app.logger.info(f"Audience created: {audience_data}")
        return jsonify(audience_data), 200

    except FacebookRequestError as fb_error:
        current_app.logger.error(f"Facebook API Error: {fb_error}")

        return jsonify({
            'error': {
                'message': fb_error.api_error_message(),
                'type': fb_error.api_error_type(),
                'code': fb_error.api_error_code(),
                'fbtrace_id': fb_error.api_error_fbtrace_id()
            }
        }), fb_error.http_status()

    except Exception as e:
        logging.error(f"General Error: {str(e)}")
        return jsonify({'error': str(e)}), 500
def read_single_audience(app_id, app_secret, access_token, audience_id):
    try:
        logging.debug(f"Initializing Facebook API with app_id={app_id}, app_secret=****, access_token=****")
        FacebookAdsApi.init(app_id, app_secret, access_token, api_version='v20.0')
        
        logging.debug(f"Fetching custom audience with custom audience id={audience_id}")
        audience = CustomAudience(audience_id).api_get(fields=custom_audience_fields)
        
        # Convert the CustomAudience object to a JSON-serializable dictionary
        audience_data = {
            'account_id': audience.get('account_id'),
            'id': audience.get('id'),
            'name': audience.get('name'),
            'description': audience.get('description')

        }
        
        logging.debug(f"Retrieved audience: {audience_data}")
        return jsonify(audience_data), 200
    
    except FacebookRequestError as fb_error:
        logging.error(f"FacebookRequestError: {str(fb_error)}")
        return jsonify({
            'error': {
                'message': fb_error.api_error_message(),
                'type': fb_error.api_error_type(),
                'code': fb_error.api_error_code(),
                'fbtrace_id': fb_error.api_error_fbtrace_id()
            }
        }), fb_error.http_status()
    
    except Exception as e:
        logging.error(f"General Error: {str(e)}")
        return jsonify({'error': str(e)}), 500  # Ensure this returns a valid JSON response
        
def read_all_audiences(app_id, app_secret, access_token, ad_account_id):
    try:
        logging.debug(f"Initializing Facebook API with app_id={app_id}, app_secret=****, access_token=****, ad_account_id={ad_account_id}")
        FacebookAdsApi.init(app_id, app_secret, access_token, api_version='v20.0')
        
        logging.debug(f"Fetching custom audiences for ad_account_id={ad_account_id}")
        audiences_cursor = AdAccount(ad_account_id).get_custom_audiences(fields=custom_audience_fields)
        
        # Convert the Cursor object to a list of dictionaries
        audiences = []
        for audience in audiences_cursor:
            audience_data = {
                'account_id': audience.get('account_id'),
                'id': audience.get('id'),
                'name': audience.get('name'),
                'description': audience.get('description')
            }
            audiences.append(audience_data)
        
        current_app.logger.info(f"Audiences: {audiences}")
        return jsonify(audiences), 200
    
    except FacebookRequestError as fb_error:
        return jsonify({
            'error': {
                'message': fb_error.api_error_message(),
                'type': fb_error.api_error_type(),
                'code': fb_error.api_error_code(),
                'fbtrace_id': fb_error.api_error_fbtrace_id()
            }
        }), fb_error.http_status()

    except Exception as e:
        return jsonify({'error': str(e)}), 500

        
def custom_audience_update(app_id, app_secret, access_token, audience_id, req_params):
    try:
        FacebookAdsApi.init(app_id, app_secret, access_token, api_version='v20.0')
        
        params = {key: value for key, value in {
            'name': req_params.get('name'),
            'description': req_params.get('description'),
            'customer_file_source': req_params.get('customer_file_source'),
            'allowed_domains': req_params.get('allowed_domains'),
            'claim_objective': req_params.get('claim_objective'),
            'content_type': req_params.get('content_type'),
            # 'dataset_id': req_params.get('dataset_id'),
            'enable_fetch_or_create': req_params.get('enable_fetch_or_create'),
            'event_source_group': req_params.get('event_source_group'),
            'event_sources': req_params.get('event_sources'),
            # 'is_value_based': req_params.get('is_value_based'),
            # 'list_of_accounts': req_params.get('list_of_accounts'),
            'lookalike_spec': req_params.get('lookalike_spec'),
            'opt_out_link': req_params.get('opt_out_link'),
            # 'origin_audience_id': req_params.get('origin_audience_id'),
            # 'pixel_id': req_params.get('pixel_id'),
            # 'prefill': req_params.get('prefill'),
            'product_set_id': req_params.get('product_set_id'),
            'retention_days': req_params.get('retention_days'),
            'rule': req_params.get('rule'),
            'rule_aggregation': req_params.get('rule_aggregation'),
            'use_in_campaigns': req_params.get('use_in_campaigns')
        }.items() if value is not None and value != ""}
        logging.debug(f"Updating custom audience with ID: {audience_id} using params: {params}")
        audience = CustomAudience(audience_id).api_update(fields=custom_audience_fields,params=params)
        
        # Serialize the CustomAudience object to a dictionary
        audience_data = {
            'account_id': audience['account_id'],
            'id': audience['id'],
            'name': audience['name'],
            'description': audience.get('description', ''),
        }
        
        current_app.logger.info(f"Audience created: {audience_data}")
        return jsonify(audience_data), 200
    
    except FacebookRequestError as e:
        logging.error(f"FacebookRequestError: {str(e)}")
        return jsonify({
            'error': str(e)  # Convert the exception to a string
        }), e.http_status()
    
    except Exception as e:
        logging.error(f"General Error: {str(e)}")
        return jsonify({'error': str(e)}), 500 
     
def custom_audience_delete(app_id, app_secret, access_token, audience_id):
    try:
        FacebookAdsApi.init(app_id, app_secret, access_token, api_version='v20.0')
        audience = CustomAudience(audience_id).api_delete()
        audience_data = {
            'id': audience['id'],
        }
        return jsonify(audience_data), 200

    except FacebookRequestError as e:
        logging.error(f"FacebookRequestError: {str(e)}")
        return jsonify({
            'error': {str(e)}
        }
        ), e.http_status()
    except Exception as e:
        logging.error(f"General Error: {str(e)}")