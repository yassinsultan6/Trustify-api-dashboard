# app/utils.py
import functools
from flask import request, jsonify
from app.models import PurchasedAPI
from app.extensions import db
import time
import logging # Good practice for logging API calls
import paypalrestsdk
import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)

# --- Token Caching (Simple In-Memory Example) ---
_paypal_token_cache = {
    "access_token": None,
    "expires_at": 0  # Timestamp for when the token expires
}

def require_api_key(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("X-API-KEY")
        if not api_key:
            return jsonify({"error": "API key is missing"}), 401

        purchase = PurchasedAPI.query.filter_by(api_key=api_key).first()
        if not purchase:
            return jsonify({"error": "Invalid API key"}), 403

        return f(*args, **kwargs)
    return decorated_function


def _get_paypal_config():
    """Gets PayPal configuration, preferring SDK config, then env vars."""
    try:
        # Try to get from configured paypalrestsdk first
        sdk_options = paypalrestsdk.api.default().options
        client_id = sdk_options['client_id']
        client_secret = sdk_options['client_secret']
        mode = sdk_options.get('mode', 'sandbox') # Default to sandbox if not in SDK options
        return client_id, client_secret, mode.lower() == "sandbox"
    except (AttributeError, KeyError, TypeError):
        logger.warning("PayPal SDK not fully configured or credentials missing from SDK. Falling back to environment variables for token.")
        client_id = os.environ.get('PAYPAL_CLIENT_ID')
        client_secret = os.environ.get('PAYPAL_CLIENT_SECRET')
        mode_str = os.environ.get('PAYPAL_MODE', 'sandbox')
        if not client_id or not client_secret:
            logger.error("PAYPAL_CLIENT_ID or PAYPAL_CLIENT_SECRET not found in SDK config or environment variables.")
            return None, None, True # Default to sandbox mode on error
        return client_id, client_secret, mode_str.lower() == "sandbox"


def _get_paypal_access_token():
    """
    Fetches a PayPal access token, using a simple in-memory cache.
    Returns the access token string or None if an error occurs.
    """
    global _paypal_token_cache
    current_time = time.time()

    if _paypal_token_cache["access_token"] and _paypal_token_cache["expires_at"] > current_time:
        logger.debug("Using cached PayPal access token.")
        return _paypal_token_cache["access_token"]

    client_id, client_secret, is_sandbox = _get_paypal_config()
    if not client_id or not client_secret:
        return None # Error already logged by _get_paypal_config

    logger.info(f"Fetching new PayPal access token for {'sandbox' if is_sandbox else 'live'} mode.")
    token_url = f"https://api-m.{'sandbox.' if is_sandbox else ''}paypal.com/v1/oauth2/token"

    try:
        token_response = requests.post(
            token_url,
            auth=HTTPBasicAuth(client_id, client_secret),
            data={"grant_type": "client_credentials"},
            headers={"Accept": "application/json", "Accept-Language": "en_US"},
            timeout=10
        )
        token_response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        expires_in = token_data.get("expires_in", 3600)  # Default to 1 hour

        if not access_token:
            logger.error(f"Failed to get access_token from PayPal. Response: {token_data}")
            return None

        _paypal_token_cache["access_token"] = access_token
        # Refresh token 5 minutes before it actually expires
        _paypal_token_cache["expires_at"] = current_time + expires_in - 300
        logger.info("Successfully fetched and cached new PayPal access token.")
        return access_token

    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error getting PayPal token: {e.response.status_code} - {e.response.text}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request exception getting PayPal token: {e}")
        return None
    except ValueError:  # JSONDecodeError inherits from ValueError
        logger.error("Failed to decode JSON response for PayPal token.")
        return None

def _get_paypal_headers():
    """
    Returns the headers required for PayPal API calls, including a Bearer token.
    Returns None if token acquisition fails.
    """
    access_token = _get_paypal_access_token()
    if not access_token:
        return None
    return {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
        # Consider adding "PayPal-Request-Id": str(uuid.uuid4()) for idempotency
    }