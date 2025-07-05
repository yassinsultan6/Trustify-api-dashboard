from flask import Blueprint, render_template, redirect, url_for, flash, session, request, jsonify
from app.forms import LoginForm, SignupForm, EditUserForm, AdminSignupForm
from app.models import User, Admin, API, PurchasedAPI, PaymobOrder
from datetime import datetime
from app.extensions import db
import hashlib, uuid, os, functools, smtplib, requests
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import logging
logger = logging.getLogger(__name__)
import time
load_dotenv()

main = Blueprint('main', __name__)


PAYMOB_API_URL = "https://accept.paymobsolutions.com/api"
API_KEY = os.getenv("PAYMOB_API_KEY")
MERCHANT_ID = os.getenv("PAYMOB_MERCHANT_ID")
INTEGRATION_ID = os.getenv("PAYMOB_INTEGRATION_ID")
IFRAME_ID = os.getenv("PAYMOB_IFRAME_ID")
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

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
    
    user = User.query.get_or_404(user_id)
    
    form = EditUserForm(request.form if request.method == 'POST' else None, obj=user)
    email_exists = False 

    if form.validate_on_submit():
        
        if form.email.data.lower() != user.email.lower(): 
            existing_user_with_new_email = User.query.filter(User.email == form.email.data, User.id != user_id).first()
            if existing_user_with_new_email:
                form.email.errors.append("This email address is already registered by another user.")
                
            
        if not form.errors: 
            user.name = form.name.data
            user.email = form.email.data 
            user.phone = form.phone.data
            if form.password.data:  
                user.password = generate_password_hash(form.password.data) 
            
            try:
                db.session.commit()
                flash('User details updated successfully.', 'success')
                return redirect(url_for('main.users'))
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error updating user {user_id}: {e}")
                flash('An error occurred while updating the user.', 'danger')
    
    
    return render_template('edit_user.html', form=form, user=user) 

@main.route('/user/delete/<int:user_id>')
def delete_user(user_id):
    if 'admin_id' not in session:  
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

def generate_api_key(user_id, api_id, transaction_id):
    unique_string = f"{transaction_id}-{uuid.uuid4()}"
    api_key = hashlib.sha256(unique_string.encode()).hexdigest()

    new_key = PurchasedAPI(user_id=user_id, api_id=api_id, api_key=api_key, transaction_id=transaction_id)
    db.session.add(new_key)
    db.session.commit()

    return api_key

from functools import wraps

def require_api_key(f):
    @wraps(f)
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
                session['admin_id'] = admin.id  
                flash('Admin login successful!', 'success')
                return redirect(url_for('main.dashboard'))  
            else:
                flash('Login failed. Incorrect password for admin.', 'danger')

        else:
            flash('Login failed. No user found with that email.', 'danger')

    return render_template('login.html', form=form)

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    email_exists = False  

    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        existing_admin = Admin.query.filter_by(email=form.email.data).first()

        if existing_user or existing_admin:
            email_exists = True  
        else:
            hashed_password = generate_password_hash(form.password.data)  
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
                print(f"[SIGNUP ERROR] {e}")  
                flash(f"An error occurred: {str(e)}", 'danger')

    return render_template('signup.html', form=form, email_exists=email_exists)

@main.route('/pricing')
def pricing():
    apis = API.query.all()

    # Get user's purchased APIs if logged in
    purchased_api_ids = []
    if 'user_id' in session:
        user_id = session['user_id']
        purchased_apis = PurchasedAPI.query.filter_by(user_id=user_id).all()
        purchased_api_ids = [purchase.api_id for purchase in purchased_apis]
    
    serializable_apis = [api.to_dict() for api in apis]  

    return render_template(
        'pricing.html',
        apis=apis,  
        apis_json=serializable_apis,  
        purchased_api_ids=purchased_api_ids,
        paymob_iframe_id=os.environ.get('PAYMOB_IFRAME_ID')  
    )

@main.route('/get-api-key/<int:api_id>')
def get_api_key(api_id):
    print(f"--- Received request for API key for api_id: {api_id} ---")
    if 'user_id' not in session:
        print("--- ERROR: user_id not in session. Aborting. ---")
        return jsonify({'error': 'Authentication required. Please log in.'}), 401
    
    user_id = session['user_id']
    print(f"--- User ID from session: {user_id} ---")
    
    # Check if user has purchased this API
    purchased_api = PurchasedAPI.query.filter_by(
        user_id=user_id, 
        api_id=api_id
    ).first()
    
    if not purchased_api:
        print(f"--- ERROR: No purchase record found for user_id {user_id} and api_id {api_id}. ---")
        return jsonify({'error': 'API not purchased by this user.'}), 403
    
    print(f"--- Found purchase record: {purchased_api}. API Key: {purchased_api.api_key} ---")
    
    # Get API details
    api = API.query.get(api_id)
    if not api:
        print(f"--- ERROR: API with id {api_id} not found in API table. ---")
        return jsonify({'error': 'API details not found.'}), 404
    
    print(f"--- Found API details: {api.name} ---")
    
    response_data = {
        'api_name': api.name,
        'api_key': purchased_api.api_key,
        'purchase_date': purchased_api.created_at.isoformat() if purchased_api.created_at else None
    }
    
    print(f"--- Sending successful response: {response_data} ---")
    return jsonify(response_data)

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



def send_api_key_email(to_email, api_key):
    msg = MIMEText(f"Thank you! Your API Key:\n\n{api_key}")
    msg['Subject'] = "API Key Access"
    msg['From'] = EMAIL_USER
    msg['To'] = to_email
    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        print("Email send failed:", e)

def get_paymob_auth_token():
    response = requests.post(f"{PAYMOB_API_URL}/auth/tokens", json={"api_key": API_KEY})
    return response.json().get("token")

def create_paymob_order(auth_token, amount):
    order_data = {
        "auth_token": auth_token,
        "delivery_needed": False,
        "amount_cents": int(amount * 100),
        "currency": "EGP",
        "merchant_order_id": str(uuid.uuid4()),
        "items": [{"name": "API", "amount_cents": int(amount * 100), "quantity": 1}]
    }
    logger.info(f"Paymob Order Request: {order_data}") 
    response = requests.post(f"{PAYMOB_API_URL}/ecommerce/orders", json=order_data)
    logger.info(f"Paymob Order Response Status: {response.status_code}") 
    logger.info(f"Paymob Order Response JSON: {response.json()}") 
    response.raise_for_status() 
    return response.json().get("id")

def get_paymob_payment_key(auth_token, order_id, amount, billing_data):
    url = "https://accept.paymobsolutions.com/api/acceptance/payment_keys"
    headers = {"Content-Type": "application/json"}

    payload = {
        "auth_token": auth_token,
        "amount_cents": int(amount * 100),  
        "expiration": 3600,
        "order_id": order_id,
        "billing_data": billing_data,
        "currency": "EGP",
        "integration_id": INTEGRATION_ID
    }

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()["token"]


@main.route('/paymob-checkout/<int:api_id>/<float:price>')
def paymob_checkout(api_id, price):
    user_id = session.get("user_id")
    if not user_id:
        flash("You must be logged in to make a payment.", "danger")
        return redirect(url_for("main.login"))

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.login"))

  
    name_parts = user.name.strip().split(" ", 1)
    first_name = name_parts[0]
    last_name = name_parts[1] if len(name_parts) > 1 else "User"

    billing_data = {
        "apartment": "N/A",
        "email": user.email,
        "floor": "N/A",
        "first_name": first_name,
        "street": "N/A",
        "building": "N/A",
        "phone_number": user.phone,
        "shipping_method": "N/A",
        "postal_code": "N/A",
        "city": "Cairo",
        "country": "EG",
        "last_name": last_name,
        "state": "Cairo"
    }

    auth_token = get_paymob_auth_token()
    order_id = create_paymob_order(auth_token, price)
    payment_token = get_paymob_payment_key(auth_token, order_id, price, billing_data)
    session["pending_api_id"] = api_id
    # Save order mapping
    paymob_order = PaymobOrder(order_id=order_id, api_id=api_id, user_id=user.id)
    db.session.add(paymob_order)
    db.session.commit()

    return redirect(f"https://accept.paymobsolutions.com/api/acceptance/iframes/{IFRAME_ID}?payment_token={payment_token}")

@main.route("/payment-success")
def payment_success():
    transaction_id_from_url = request.args.get("id")
    logger.info(f"--- /payment-success: Attempting to show API key on page ---")
    logger.info(f"--- /payment-success: Received transaction_id_from_url: {transaction_id_from_url} ---")

    user_id = session.get("user_id")
    logger.info(f"--- /payment-success: Current user_id from session: {user_id} ---")

    if not user_id or not transaction_id_from_url:
        flash("Missing payment information from redirect.", "danger")
        logger.warning(f"--- /payment-success: Missing user_id ({user_id}) or transaction_id_from_url ({transaction_id_from_url}). Redirecting to pricing. ---")
        return redirect(url_for("main.pricing"))

    # user = User.query.get(user_id) 
    # if not user:
    #     flash("User not found for current session.", "danger")
    #     logger.warning(f"--- /payment-success: User not found for user_id {user_id}. Redirecting to login. ---")
    #     return redirect(url_for("main.login"))

    api_key_to_display = None
    purchased_api_record = None
    message_for_template = "Your payment was successful." 

    
    attempts = 0
    max_attempts = 10  
    retry_delay = 1   

    while attempts < max_attempts:
        logger.info(f"--- /payment-success: Attempt {attempts + 1}/{max_attempts} to find PurchasedAPI for transaction_id={transaction_id_from_url}, user_id={user_id} ---")
        purchased_api_record = PurchasedAPI.query.filter_by(
            transaction_id=str(transaction_id_from_url),
            user_id=user_id 
        ).first()

        if purchased_api_record and purchased_api_record.api_key: 
            api_key_to_display = purchased_api_record.api_key
            logger.info(f"--- /payment-success: SUCCESS! Found API Key: {api_key_to_display} on attempt {attempts + 1} ---")
            message_for_template = "Keep this key safe. You'll need it to access the API."
            
        elif purchased_api_record and not purchased_api_record.api_key:
            logger.warning(f"--- /payment-success: Record found for {transaction_id_from_url} on attempt {attempts + 1}, but api_key is NULL. Callback might have failed to set it. ---")

            message_for_template = "Your payment is confirmed, but there was an issue retrieving the API key. Please check your email or contact support."
            

        attempts += 1
        if attempts < max_attempts:
            logger.info(f"--- /payment-success: Key not yet found, sleeping for {retry_delay}s... ---")
            time.sleep(retry_delay)
        else: 
            logger.warning(f"--- /payment-success: API Key not found after {max_attempts} attempts for transaction {transaction_id_from_url}. Falling back to email notification. ---")
            message_for_template = "Your API key is being processed. You will receive it via email shortly. You can also check your profile later."
            

    session.pop("pending_api_id", None)

    logger.info(f"--- /payment-success: Rendering template with api_key: {api_key_to_display}, message: '{message_for_template}' ---")
    return render_template("payment_success.html", api_key=api_key_to_display, message=message_for_template)

@main.route('/payment-callback', methods=['POST'])
def payment_callback():
    logger.info(f"--- /payment-callback: Received a request ---")
    data = request.get_json()
    if not data:
        logger.warning(f"--- /payment-callback: No JSON data received. ---")
        return jsonify({"error": "Invalid request"}), 400

    logger.info(f"--- /payment-callback: Received data: {data} ---")

    
    transaction_obj = data.get("obj", {})
    is_success = transaction_obj.get("success")
    paymob_transaction_id = str(transaction_obj.get("id", "")) 
    paymob_order_id_from_callback = str(transaction_obj.get("order", {}).get("id", "")) 

    if is_success is not True: 
        logger.warning(f"--- /payment-callback: Unsuccessful payment or missing success flag. Success: {is_success}, TXN_ID: {paymob_transaction_id} ---")
        return jsonify({"error": "Unsuccessful payment"}), 400 

    if not paymob_transaction_id or not paymob_order_id_from_callback:
        logger.error(f"--- /payment-callback: Missing transaction_id ({paymob_transaction_id}) or order_id ({paymob_order_id_from_callback}) in callback. Data: {data} ---")
        return jsonify({"error": "Missing required payment details"}), 400

    
    paymob_order_record = PaymobOrder.query.filter_by(order_id=paymob_order_id_from_callback).first()
    if not paymob_order_record:
        logger.error(f"--- /payment-callback: PaymobOrder not found in DB for order_id: {paymob_order_id_from_callback} ---")

        return jsonify({"error": "Order not found in system"}), 404 

    user = User.query.get(paymob_order_record.user_id)
    if not user:
        logger.error(f"--- /payment-callback: User not found for user_id: {paymob_order_record.user_id} (from PaymobOrder {paymob_order_id_from_callback}) ---")
        return jsonify({"error": "User not found"}), 404 

    api_id_to_purchase = paymob_order_record.api_id
    logger.info(f"--- /payment-callback: Processing for User ID: {user.id}, API ID: {api_id_to_purchase}, Paymob TXN ID: {paymob_transaction_id} ---")

    
    existing_purchase = PurchasedAPI.query.filter_by(transaction_id=paymob_transaction_id).first()
    if existing_purchase:
        logger.info(f"--- /payment-callback: Transaction {paymob_transaction_id} already processed. API Key: {existing_purchase.api_key}. Sending 200 OK. ---")

        return jsonify({"message": "Payment already processed"}), 200

    
    unique_string_for_key = f"{paymob_transaction_id}-{uuid.uuid4()}"
    api_key_generated = hashlib.sha256(unique_string_for_key.encode()).hexdigest()
    logger.info(f"--- /payment-callback: Generated API Key: {api_key_generated} for TXN_ID: {paymob_transaction_id} ---")

    new_purchase = PurchasedAPI(
        user_id=user.id,
        api_id=api_id_to_purchase,
        api_key=api_key_generated,
        transaction_id=paymob_transaction_id
    )
    db.session.add(new_purchase)
    try:
        db.session.commit()
        logger.info(f"--- /payment-callback: SUCCESS! Committed PurchasedAPI for TXN_ID: {paymob_transaction_id} to DB. Key: {api_key_generated} ---")
    except Exception as e:
        db.session.rollback()
        logger.error(f"--- /payment-callback: DATABASE ERROR saving PurchasedAPI for TXN_ID {paymob_transaction_id}: {e} ---")
        return jsonify({"error": "Failed to save purchase record"}), 500 

    
    try:
        logger.info(f"--- /payment-callback: Attempting to send API key email to {user.email} for TXN_ID: {paymob_transaction_id} ---")
        send_api_key_email(user.email, api_key_generated)
        logger.info(f"--- /payment-callback: Email sent successfully for TXN_ID: {paymob_transaction_id} ---")
    except Exception as e:
        logger.error(f"--- /payment-callback: FAILED to send email for TXN_ID {paymob_transaction_id}: {e} ---")
        

    return jsonify({"message": "API key delivered"}), 200
@main.route('/logout')
def logout():
    # Clear all session data
    session.clear()
    return redirect(url_for("main.index"))

