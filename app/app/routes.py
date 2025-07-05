from flask import Blueprint, render_template, redirect, url_for, flash, session, request, jsonify
from app.forms import LoginForm, SignupForm, EditUserForm, AdminSignupForm
from app.models import User, Admin, API, PurchasedAPI
from datetime import datetime
import paypalrestsdk
import hashlib
import uuid
from app.utils import _get_paypal_access_token, _get_paypal_headers, _get_paypal_config
import sqlite3
import smtplib
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash, check_password_hash  
import functools
import requests
from app import create_app
from app.utils import require_api_key
from requests.auth import HTTPBasicAuth
from flask import Flask
from flask_migrate import Migrate
from app.extensions import db # Adjust this import to where your `db = SQLAlchemy()` is defined
import os
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

import logging # Good practice for logging API calls

logger = logging.getLogger(__name__)

from dotenv import load_dotenv
load_dotenv()

sender_email = os.environ.get("EMAIL_USER")
sender_password = os.environ.get("EMAIL_PASS")

paypal_client_id = os.environ.get("PAYPAL_CLIENT_ID")
paypal_client_secret = os.environ.get("PAYPAL_CLIENT_SECRET")
paypal_mode = os.environ.get("PAYPAL_MODE", "sandbox") # Default to sandbox

if not paypal_client_id or not paypal_client_secret:
    logger.critical("FATAL: PAYPAL_CLIENT_ID or PAYPAL_CLIENT_SECRET not set in environment variables!")
    # You might want to raise an exception here if PayPal is essential
    # For now, the SDK configuration will likely fail or be incomplete.
    # _get_paypal_config will also log errors if it can't find credentials.
else:
    paypalrestsdk.configure({
        "mode": paypal_mode,
        "client_id": paypal_client_id,
        "client_secret": paypal_client_secret
    })


def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    migrate.init_app(app, db) 
    
    from app.routes import main
    app.register_blueprint(main)

    @app.shell_context_processor
    def make_shell_context():
        return {'db': db}

    return app




main = Blueprint('main', __name__)

paypalrestsdk.configure({
    "mode": "sandbox",
    "client_id": "AaVLH8hyk4o-w7Yl0_zidL2hoC-5pcDqG_pskulv4PnXE8FtpYGhyWRUP14CeaEgntXDBpIEo8x90MT5",
    "client_secret": "EPmZSD9ehcL36D8qNRdzaa5sB6saFUmj5ig1Yb2sLVGV8091p1VpjvSOMU2TW1JrN3IQdy85Qvt463Et"
})

@main.route('/create-order', methods=['POST'])
def create_order():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON payload'}), 400

    price_str = data.get('price')
    api_id = data.get('api_id')

    if not api_id or not price_str:
        return jsonify({'error': 'Missing API ID or price'}), 400

    try:
        price_val = float(price_str)
        if price_val <= 0:
            return jsonify({'error': 'Price must be a positive value'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid price format. Price must be a number.'}), 400

    request_headers = _get_paypal_headers()
    if not request_headers:
        logger.error("Failed to get PayPal headers for create-order.")
        return jsonify({'error': 'Payment provider authentication failed'}), 500

    _, __, is_sandbox = _get_paypal_config() # Get sandbox status
    paypal_api_base_url = f"https://api-m.{'sandbox.' if is_sandbox else ''}paypal.com"

    order_payload = {
        "intent": "CAPTURE",
        "purchase_units": [{
            "amount": {
                "currency_code": "USD",
                "value": f"{price_val:.2f}"
            },
            "description": f"Purchase of API ID: {api_id}", # Optional: Add a description
            "custom_id": str(api_id) # Useful for your internal tracking
        }],
        # Optional: If you want PayPal to handle redirects (less common with JS SDK client-side approval)
        # "application_context": {
        # "return_url": url_for('main.payment_success_handler_route_name', _external=True), # Adjust route name
        # "cancel_url": url_for('main.payment_cancel', _external=True)
        # }
    }

    try:
        logger.info(f"Creating PayPal order with payload: {order_payload}")
        order_response = requests.post(
            f"{paypal_api_base_url}/v2/checkout/orders",
            headers=request_headers,
            json=order_payload,
            timeout=15 # Add a timeout
        )
        order_response.raise_for_status()  # Will raise an HTTPError for bad status codes
        response_data = order_response.json()
        logger.info(f"PayPal order created successfully: ID {response_data.get('id')}")
        return jsonify(response_data)

    except requests.exceptions.HTTPError as e:
        error_details = "Unknown error from payment provider."
        try:
            error_details = e.response.json()
        except ValueError: # If response is not JSON
            error_details = e.response.text
        logger.error(f"HTTP error creating PayPal order: {e.response.status_code} - {error_details}")
        return jsonify({'error': 'Failed to create payment order with provider.', 'details': error_details}), e.response.status_code
    except requests.exceptions.RequestException as e: # For network errors, timeouts, etc.
        logger.error(f"Request exception creating PayPal order: {e}")
        return jsonify({'error': 'Network error while communicating with payment provider.'}), 500
    except ValueError: # If order_response.json() fails
        logger.error("Failed to decode JSON response from PayPal order creation.")
        return jsonify({'error': 'Invalid response from payment provider.'}), 500

@main.route('/apis', methods=['GET'])
def apis():
    api_list = API.query.all()
    return render_template('apis.html', api_list=api_list)
@main.route('/edit_api/<int:api_id>', methods=['GET', 'POST'])
def edit_api(api_id):
    api = API.query.get_or_404(api_id)

    if request.method == 'POST':
        api.name = request.form['name']
        api.price = request.form['price']
        db.session.commit()
        flash('API details updated successfully!', 'success')
        return redirect(url_for('main.apis'))

    return render_template('edit_api.html', api=api)

@main.route('/add_api', methods=['GET', 'POST'])
def add_api():
    if 'admin_id' not in session:  
        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for('main.login'))
    
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        price = request.form['price']

        # Create a new API object
        new_api = API(name=name, price=float(price))

        # Add to the database
        db.session.add(new_api)
        db.session.commit()

        flash('API added successfully!', 'success')
        return redirect(url_for('main.apis'))  

    return render_template('add_api.html')

@main.route('/dashboard')
def dashboard():
    if 'admin_id' not in session:  
        flash('You need to log in as an admin to access the dashboard.', 'danger')
        return redirect(url_for('main.login'))

    admin = Admin.query.get(session['admin_id'])  
    if not admin:
        flash('Admin not found.', 'danger')
        session.pop('admin_id', None)  
        return redirect(url_for('main.login'))

    return render_template('dashboard.html', admin=admin)  


@main.route('/profile')
def profile():
    if 'admin_id' not in session:
        flash('You need to log in as an admin to access the profile page.', 'danger')
        return redirect(url_for('main.login'))

    admin = Admin.query.get(session['admin_id'])
    if not admin:
        flash('Admin not found.', 'danger')
        return redirect(url_for('main.login'))

    return render_template('profile.html', user=admin)

@main.route('/users')
def users():
    if 'admin_id' not in session: 
        flash('You need to log in as an admin to access the dashboard.', 'danger')
        return redirect(url_for('main.login'))

    all_users = User.query.all()
    return render_template('users.html', users=all_users)

@main.route('/user/<int:user_id>')
def view_user(user_id):
    if 'admin_id' not in session:  
        flash('You need to log in as an admin to view user details.', 'danger')
        return redirect(url_for('main.login'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('main.users'))

    return render_template('view_user.html', user=user)

@main.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    # ... (admin check, existing user query) ...
    user = User.query.get_or_404(user_id)
    # For GET, pre-populate. For POST, use submitted data.
    form = EditUserForm(request.form if request.method == 'POST' else None, obj=user)
    email_exists = False # This logic needs to be robust

    if form.validate_on_submit():
        # Check if email is being changed and if the new one exists
        if form.email.data.lower() != user.email.lower(): # Check if email actually changed
            existing_user_with_new_email = User.query.filter(User.email == form.email.data, User.id != user_id).first()
            if existing_user_with_new_email:
                form.email.errors.append("This email address is already registered by another user.")
                # No need for the separate email_exists flag if using form errors
            
        if not form.errors: # Proceed if no validation errors
            user.name = form.name.data
            user.email = form.email.data # Already checked for uniqueness if changed
            user.phone = form.phone.data
            if form.password.data:  # Only update password if a new one is provided
                user.password = generate_password_hash(form.password.data) # HASH THE PASSWORD
            
            try:
                db.session.commit()
                flash('User details updated successfully.', 'success')
                return redirect(url_for('main.users'))
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error updating user {user_id}: {e}")
                flash('An error occurred while updating the user.', 'danger')
    
    # If GET or form validation failed
    return render_template('edit_user.html', form=form, user=user) # form.errors will be available in template

@main.route('/user/delete/<int:user_id>')
def delete_user(user_id):
    if 'admin_id' not in session:  # Check if an admin is logged in
        flash('You need to log in as an admin to delete a user.', 'danger')
        return redirect(url_for('main.login'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    else:
        flash('User not found.', 'danger')
    
    return redirect(url_for('main.users'))

def generate_api_key(transaction_id, api_id):
    unique_string = f"{transaction_id}-{uuid.uuid4()}"
    api_key = hashlib.sha256(unique_string.encode()).hexdigest()
    db.session.commit()
    return api_key


def send_api_key_email(to_email, api_key):
    import os
    sender_email = os.environ.get("EMAIL_USER")
    sender_password = os.environ.get("EMAIL_PASS")

    subject = "Your API Key"
    body = f"Thank you for your payment! Here is your API key:\n\n{api_key}\n\nKeep it safe."
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email

    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        print("Failed to send email:", e)


def verify_paypal_order(order_id):
    request_headers = _get_paypal_headers()
    if not request_headers:
        logger.error(f"Failed to get PayPal headers for verifying order {order_id}.")
        return None # Indicates failure to get token/headers

    _, __, is_sandbox = _get_paypal_config()
    paypal_api_base_url = f"https://api-m.{'sandbox.' if is_sandbox else ''}paypal.com"
    order_details_url = f"{paypal_api_base_url}/v2/checkout/orders/{order_id}"

    try:
        logger.info(f"Verifying PayPal order {order_id}")
        order_response = requests.get(
            order_details_url,
            headers=request_headers,
            timeout=10
        )
        order_response.raise_for_status()
        order_data = order_response.json()

        # IMPORTANT: Verify not just "COMPLETED", but also the amount and currency
        # match what you expect for that order_id to prevent tampering.
        # This requires fetching the original amount from your database or session.
        # For now, just checking status:
        if order_data.get("status") == "COMPLETED":
            logger.info(f"PayPal order {order_id} is COMPLETED.")
            # Example: (You'd need to fetch expected_amount and expected_currency)
            # purchase_unit = order_data.get('purchase_units', [{}])[0]
            # amount_paid = purchase_unit.get('amount', {}).get('value')
            # currency_paid = purchase_unit.get('amount', {}).get('currency_code')
            # if str(amount_paid) == str(expected_amount) and currency_paid == expected_currency:
            #    return order_data
            # else:
            #    logger.error(f"Order {order_id} amount/currency mismatch! Expected {expected_amount} {expected_currency}, got {amount_paid} {currency_paid}")
            #    return None
            return order_data
        else:
            logger.warning(f"PayPal order {order_id} status is '{order_data.get('status')}', not COMPLETED.")
            return None # Order not completed or status incorrect

    except requests.exceptions.HTTPError as e:
        error_details = "Unknown error"
        try: error_details = e.response.json()
        except ValueError: error_details = e.response.text
        if e.response.status_code == 404:
            logger.warning(f"PayPal order {order_id} not found (404).")
        else:
            logger.error(f"HTTP error verifying PayPal order {order_id}: {e.response.status_code} - {error_details}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request exception verifying PayPal order {order_id}: {e}")
        return None
    except ValueError: # JSONDecodeError
        logger.error(f"Failed to decode JSON response for PayPal order {order_id}.")
        return None

def require_api_key(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("X-API-KEY")
        if not api_key:
            return jsonify({"error": "API key is missing"}), 401
        valid_key = PurchasedAPI.query.filter_by(api_key=api_key).first()

        if not valid_key:
            return jsonify({"error": "Invalid API key"}), 403
        return f(*args, **kwargs)
    return decorated_function

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        admin = Admin.query.filter_by(email=form.email.data).first()

        if user:
            if check_password_hash(user.password, form.password.data):  
                session.clear()  
                session['user_id'] = user.id  
                flash('Login successful!', 'success')
                return redirect(url_for('main.pricing'))  
            else:
                flash('Login failed. Incorrect password for user.', 'danger')

       
        elif admin:
            if check_password_hash(admin.password, form.password.data):  
                session.clear() 
                session['admin_id'] = admin.id  #
                flash('Admin login successful!', 'success')
                return redirect(url_for('main.dashboard'))  
            else:
                flash('Login failed. Incorrect password for admin.', 'danger')

        else:
            flash('Login failed. No user or admin found with that email.', 'danger')

    return render_template('login.html', form=form)

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    email_exists = False  

    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        existing_admin = Admin.query.filter_by(email=form.email.data).first()

        if existing_user or existing_admin:
            email_exists = True  # Email already exists in either table
        else:
            hashed_password = generate_password_hash(form.password.data)  # Hash the password
            user = User(
                name=form.name.data, 
                email=form.email.data, 
                phone=form.phone.data, 
                password=hashed_password  
            )
            try:
                db.session.add(user)
                db.session.commit()
                flash('Account created successfully!', 'success')
                return redirect(url_for('main.login'))
            except Exception as e:
                db.session.rollback()
                print(f"[SIGNUP ERROR] {e}")  # <-- Add this line
                flash(f"An error occurred: {str(e)}", 'danger')

    return render_template('signup.html', form=form, email_exists=email_exists)



@main.route('/pricing')
def pricing():
    apis = API.query.all()

    # Convert to serializable format
    serializable_apis = [api.to_dict() for api in apis]  # Use to_dict() here

    return render_template(
        'pricing.html',
        apis=apis,  # Pass the full API objects (for rendering)
        apis_json=serializable_apis,  # Pass the serialized APIs for JavaScript
        paypal_client_id=os.environ.get('PAYPAL_CLIENT_ID')
    )






@main.route('/payment-cancel')
def payment_cancel():
    return "Payment was canceled.", 400

@main.route('/payment-success', methods=['POST'])
def payment_success():
    data = request.get_json()
    order_id = data.get('orderID')
    api_id = data.get('api_id')
    user_id = session.get('user_id')

    if not order_id or not api_id or not user_id:
        return jsonify({"error": "Missing required data"}), 400

    order_data = verify_paypal_order(order_id)
    if not order_data:
        return jsonify({"error": "Payment verification failed"}), 400

    api_key = generate_api_key(order_id, api_id)

    new_purchase = PurchasedAPI(
        user_id=user_id,
        api_id=api_id,
        transaction_id=order_id,
        api_key=api_key
    )
    db.session.add(new_purchase)
    db.session.commit()

    user = User.query.get(user_id)
    send_api_key_email(user.email, api_key)

    return jsonify({"success": True, "message": "API key sent to email."})


@main.route('/add_admin', methods=['GET', 'POST'])
def add_admin():
    if 'admin_id' not in session:  
        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for('main.login'))
    
    form = AdminSignupForm()  
    email_exists = False  

    if form.validate_on_submit():  
        existing_admin = Admin.query.filter_by(email=form.email.data).first()
        existing_user = User.query.filter_by(email=form.email.data).first()

        if existing_admin or existing_user:
            email_exists = True  
        else:
            new_admin = Admin(
                name=form.name.data, 
                email=form.email.data, 
                phone=form.phone.data, 
                password=generate_password_hash(form.password.data)  
            )
            db.session.add(new_admin)
            db.session.commit()
            flash('Admin account created successfully!', 'success')
            return redirect(url_for('main.dashboard'))  

    return render_template('add_admin.html', form=form, email_exists=email_exists)  

@main.route('/delete_api/<int:api_id>', methods=['GET'])
def delete_api(api_id):
    api = API.query.get_or_404(api_id)
    db.session.delete(api)
    db.session.commit()
    flash('API deleted successfully!', 'success')
    return redirect(url_for('main.apis'))

@main.route('/capture-order/<order_id>', methods=['POST'])
def capture_order(order_id):
    request_headers = _get_paypal_headers()
    if not request_headers:
        logger.error(f"Failed to get PayPal headers for capturing order {order_id}.")
        return jsonify({'error': 'Payment provider authentication failed'}), 500

    _, __, is_sandbox = _get_paypal_config()
    paypal_api_base_url = f"https://api-m.{'sandbox.' if is_sandbox else ''}paypal.com"
    capture_url = f"{paypal_api_base_url}/v2/checkout/orders/{order_id}/capture"

    try:
        logger.info(f"Capturing PayPal order {order_id}")
        capture_response = requests.post(
            capture_url,
            headers=request_headers,
            json={}, # Capture usually doesn't need a body unless specifying amount for partial capture
            timeout=15
        )
        capture_response.raise_for_status()
        response_data = capture_response.json()
        logger.info(f"PayPal order {order_id} captured successfully. Status: {response_data.get('status')}")
        # Check if response_data['status'] is 'COMPLETED'
        return jsonify(response_data)

    except requests.exceptions.HTTPError as e:
        error_details = "Unknown error"
        try: error_details = e.response.json()
        except ValueError: error_details = e.response.text
        logger.error(f"HTTP error capturing PayPal order {order_id}: {e.response.status_code} - {error_details}")
        return jsonify({'error': 'Failed to capture payment with provider.', 'details': error_details}), e.response.status_code
    except requests.exceptions.RequestException as e:
        logger.error(f"Request exception capturing PayPal order {order_id}: {e}")
        return jsonify({'error': 'Network error while capturing payment.'}), 500
    except ValueError:
        logger.error(f"Failed to decode JSON response from PayPal capture for order {order_id}.")
        return jsonify({'error': 'Invalid response from payment provider after capture.'}), 500


@main.route('/logout')
def logout():
    session.pop('admin_id', None)
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.index'))
