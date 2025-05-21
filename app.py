import os
import uuid
import json
import logging
import boto3
import bcrypt
import random
import string
from datetime import datetime, timedelta
from decimal import Decimal
from functools import wraps
from dotenv import load_dotenv
from botocore.exceptions import ClientError
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.utils import secure_filename

# --------------------------------------- #
# Load Environment Variables
# --------------------------------------- #
if not load_dotenv():
    raise FileNotFoundError(".env file not found. Make sure it exists for environment configuration.")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --------------------------------------- #
# Flask App Initialization
# --------------------------------------- #
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session timeout after 1 hour
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --------------------------------------- #
# App Configuration
# --------------------------------------- #
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'ap-south-1')

# Email Configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
ENABLE_EMAIL = os.environ.get('ENABLE_EMAIL', 'False').lower() == 'true'

# DynamoDB Table Names
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'UsersTable')
PROPERTIES_TABLE_NAME = os.environ.get('PROPERTIES_TABLE_NAME', 'PropertiesTable')
APPLICATIONS_TABLE_NAME = os.environ.get('APPLICATIONS_TABLE_NAME', 'ApplicationsTable')
BOOKINGS_TABLE_NAME = os.environ.get('BOOKINGS_TABLE_NAME', 'BookingsTable')

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'False').lower() == 'true'

# Login attempt tracking for rate limiting
login_attempts = {}

# --------------------------------------- #
# AWS Resources Initialization
# --------------------------------------- #
try:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
    sns = boto3.client('sns', region_name=AWS_REGION_NAME)

    user_table = dynamodb.Table(USERS_TABLE_NAME)
    property_table = dynamodb.Table(PROPERTIES_TABLE_NAME)
    application_table = dynamodb.Table(APPLICATIONS_TABLE_NAME)
    booking_table = dynamodb.Table(BOOKINGS_TABLE_NAME)
except Exception as e:
    logger.error(f"Error initializing AWS resources: {e}")
    raise

# --------------------------------------- #
# Helper Functions
# --------------------------------------- #
def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Type {type(obj)} not serializable")

def hash_password(password):
    """Hash a password for storing."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(stored_password, provided_password):
    if isinstance(stored_password, str):
        stored_password = stored_password.encode('utf-8')
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

def generate_random_id(prefix='', length=8):
    """Generate a random ID with optional prefix"""
    chars = string.ascii_uppercase + string.digits
    random_string = ''.join(random.choice(chars) for _ in range(length))
    return f"{prefix}{random_string}"

def send_email(recipient, subject, body):
    """Send email using SMTP"""
    if not ENABLE_EMAIL:
        logger.info(f"Email sending disabled. Would have sent to {recipient}: {subject}")
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        
        logger.info(f"Email sent to {recipient}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False

def send_sms_notification(phone_number, message):
    """Send SMS notification using AWS SNS"""
    if not ENABLE_SNS:
        logger.info(f"SNS disabled. Would have sent to {phone_number}: {message}")
        return False
    
    try:
        response = sns.publish(
            PhoneNumber=phone_number,
            Message=message,
            MessageAttributes={
                'AWS.SNS.SMS.SenderID': {
                    'DataType': 'String',
                    'StringValue': 'PropertyApp'
                }
            }
        )
        logger.info(f"SMS sent to {phone_number}, MessageId: {response['MessageId']}")
        return True
    except Exception as e:
        logger.error(f"Failed to send SMS: {e}")
        return False

def send_notification(user_id, notification_type, message, additional_data=None):
    """Send notification based on user preferences"""
    try:
        # Get user details including communication preferences
        user_response = user_table.get_item(
            Key={'user_id': user_id}
        )
        
        if 'Item' not in user_response:
            logger.error(f"User {user_id} not found for notification")
            return False
        
        user = user_response['Item']
        
        # Prepare notification data to store
        notification_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        notification_data = {
            'notification_id': notification_id,
            'user_id': user_id,
            'type': notification_type,
            'message': message,
            'timestamp': timestamp,
            'read': False
        }
        
        if additional_data:
            notification_data['additional_data'] = additional_data
        
        # Store notification in DynamoDB (if you decide to create a notifications table)
        # notifications_table.put_item(Item=notification_data)
        
        # Send email if user has email notifications enabled
        if user.get('email_notifications', True) and 'email' in user:
            send_email(user['email'], f"Property App: {notification_type}", message)
        
        # Send SMS if user has SMS notifications enabled
        if user.get('sms_notifications', False) and 'phone' in user:
            send_sms_notification(user['phone'], message)
        
        return True
    except Exception as e:
        logger.error(f"Error sending notification: {e}")
        return False

# --------------------------------------- #
# Authentication Decorators
# --------------------------------------- #
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page', 'warning')
                return redirect(url_for('login', next=request.url))
            
            if session.get('role') not in allowed_roles:
                flash('You do not have permission to access this page', 'danger')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --------------------------------------- #
# Authentication Routes
# --------------------------------------- #
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        email = request.form.get('email').lower()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        name = request.form.get('name')
        phone = request.form.get('phone')
        role = request.form.get('role', 'tenant')  # Default role is tenant
        
        # Validate inputs
        if not all([email, password, confirm_password, name]):
            flash('Please fill all required fields', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        # Validate role (prevent users from creating admin accounts)
        if role == 'admin' and not session.get('is_admin', False):
            role = 'tenant'  # Force to tenant if not already an admin
        
        # Check if user already exists
        try:
            response = user_table.query(
                IndexName='EmailIndex',
                KeyConditionExpression=boto3.dynamodb.conditions.Key('email').eq(email)
            )
            
            if response['Items']:
                flash('Email already registered', 'danger')
                return render_template('register.html')
            
            # Create new user
            user_id = str(uuid.uuid4())
            hashed_password = hash_password(password).decode('utf-8')
            
            user_data = {
                'user_id': user_id,
                'email': email,
                'password': hashed_password,
                'name': name,
                'phone': phone,
                'role': role,
                'email_notifications': True,
                'sms_notifications': False,
                'created_at': datetime.now().isoformat(),
                'status': 'active'
            }
            
            user_table.put_item(Item=user_data)
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash('An error occurred during registration', 'danger')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')
        
        # Rate limiting check
        ip = request.remote_addr
        current_time = datetime.now()
        
        if ip in login_attempts:
            attempts = [t for t in login_attempts[ip] if (current_time - t).total_seconds() < 3600]
            if len(attempts) >= 5:
                flash('Too many login attempts. Please try again later.', 'danger')
                return render_template('login.html')
            login_attempts[ip] = attempts
        
        # Add this attempt
        if ip not in login_attempts:
            login_attempts[ip] = []
        login_attempts[ip].append(current_time)
        
        try:
            # Query user by email
            response = user_table.query(
                IndexName='EmailIndex',
                KeyConditionExpression=boto3.dynamodb.conditions.Key('email').eq(email)
            )
            
            if not response['Items']:
                flash('Invalid email or password', 'danger')
                return render_template('login.html')
            
            user = response['Items'][0]
            
            # Check if account is active
            if user.get('status') != 'active':
                flash('Your account is not active. Please contact support.', 'danger')
                return render_template('login.html')
            
            # Verify password
            if not verify_password(user['password'], password):
                flash('Invalid email or password', 'danger')
                return render_template('login.html')
            
            # Set session data
            session['user_id'] = user['user_id']
            session['name'] = user['name']
            session['email'] = user['email']
            session['role'] = user['role']
            session['is_admin'] = (user['role'] == 'admin')
            session.permanent = True
            
            # Clear login attempts on successful login
            if ip in login_attempts:
                del login_attempts[ip]
            
            # Redirect based on role
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred during login', 'danger')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session.get('user_id')
    
    if request.method == 'POST':
        try:
            # Update user profile data
            name = request.form.get('name')
            phone = request.form.get('phone')
            email_notifications = 'email_notifications' in request.form
            sms_notifications = 'sms_notifications' in request.form
            
            # Update password if provided
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            update_expression = "SET #name = :name, #phone = :phone, #email_notif = :email_notif, #sms_notif = :sms_notif"
            expression_attribute_names = {
                '#name': 'name',
                '#phone': 'phone',
                '#email_notif': 'email_notifications',
                '#sms_notif': 'sms_notifications'
            }
            expression_attribute_values = {
                ':name': name,
                ':phone': phone,
                ':email_notif': email_notifications,
                ':sms_notif': sms_notifications
            }
            
            # If changing password
            if current_password and new_password:
                if new_password != confirm_password:
                    flash('New passwords do not match', 'danger')
                    return redirect(url_for('profile'))
                
                # Get current user data to verify password
                user_response = user_table.get_item(Key={'user_id': user_id})
                
                if 'Item' not in user_response:
                    flash('User not found', 'danger')
                    return redirect(url_for('dashboard'))
                
                user = user_response['Item']
                
                # Verify current password
                if not verify_password(user['password'], current_password):
                    flash('Current password is incorrect', 'danger')
                    return redirect(url_for('profile'))
                
                # Add password to update expression
                update_expression += ", #password = :password"
                expression_attribute_names['#password'] = 'password'
                expression_attribute_values[':password'] = hash_password(new_password).decode('utf-8')
            
            # Update user in DynamoDB
            user_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression=update_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_attribute_values
            )
            
            # Update session data
            session['name'] = name
            
            flash('Profile updated successfully', 'success')
            return redirect(url_for('profile'))
            
        except Exception as e:
            logger.error(f"Profile update error: {e}")
            flash('An error occurred while updating profile', 'danger')
    
    # Get user data for display
    try:
        user_response = user_table.get_item(Key={'user_id': user_id})
        
        if 'Item' not in user_response:
            flash('User not found', 'danger')
            return redirect(url_for('dashboard'))
        
        user = user_response['Item']
        return render_template('profile.html', user=user)
        
    except Exception as e:
        logger.error(f"Error retrieving user profile: {e}")
        flash('An error occurred while retrieving profile', 'danger')
        return redirect(url_for('dashboard'))

# --------------------------------------- #
# Dashboard Routes
# --------------------------------------- #
@app.route('/')
def index():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        # Here you could implement email sending functionality
        # For now, just show a success message
        try:
            # Example: record the contact request in DynamoDB
            contact_id = str(uuid.uuid4())
            contact_data = {
                'contact_id': contact_id,
                'name': name,
                'email': email,
                'subject': subject,
                'message': message,
                'created_at': datetime.now().isoformat(),
                'status': 'unread'
            }
            
            # Uncomment if you have a contact_table
            # contact_table.put_item(Item=contact_data)
            
            flash('Thank you for your message! We will get back to you soon.', 'success')
            return redirect(url_for('contact'))
        except Exception as e:
            logger.error(f"Contact form error: {e}")
            flash('An error occurred while sending your message. Please try again later.', 'danger')
            return render_template('contact.html')
    
    return render_template('contact.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_role = session.get('role')
    user_id = session.get('user_id')
    
    if user_role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif user_role == 'owner':
        return redirect(url_for('owner_dashboard'))
    else:  # tenant or default
        return redirect(url_for('tenant_dashboard'))

@app.route('/dashboard/admin')
@role_required(['admin'])
def admin_dashboard():
    try:
        # Get statistics for admin dashboard
        user_count = 0
        property_count = 0
        booking_count = 0
        application_count = 0
        
        # Count users
        response = user_table.scan(Select='COUNT')
        user_count = response.get('Count', 0)
        
        # Count properties
        response = property_table.scan(Select='COUNT')
        property_count = response.get('Count', 0)
        
        # Count bookings
        response = booking_table.scan(Select='COUNT')
        booking_count = response.get('Count', 0)
        
        # Count applications
        response = application_table.scan(Select='COUNT')
        application_count = response.get('Count', 0)
        
        # Get recent activities (example - would typically be from a separate activities table)
        recent_activities = []
        
        stats = {
            'user_count': user_count,
            'property_count': property_count,
            'booking_count': booking_count,
            'application_count': application_count
        }
        
        return render_template('admin_dashboard.html', stats=stats, activities=recent_activities)
    
    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        flash('Error loading dashboard data', 'danger')
        return render_template('admin_dashboard.html', stats={}, activities=[])

@app.route('/dashboard/owner')
@role_required(['owner'])
def owner_dashboard():
    user_id = session.get('user_id')
    
    try:
        logger.info(f"Loading owner dashboard for user: {user_id}")
        
        # Use scan instead of relying on the index
        # This is more reliable as it ensures we find all properties regardless of index issues
        try:
            scan_response = property_table.scan(
                FilterExpression=boto3.dynamodb.conditions.Attr('owner_id').eq(user_id)
            )
            properties = scan_response.get('Items', [])
            logger.info(f"Found {len(properties)} properties via scan for owner {user_id}")
            
            # Debug: Log found properties
            if properties:
                property_ids = [prop['property_id'] for prop in properties]
                logger.info(f"Property IDs found: {property_ids}")
            else:
                logger.warning(f"No properties found for owner {user_id}")
                
        except Exception as scan_error:
            logger.error(f"Property scan error: {scan_error}")
            properties = []
            property_ids = []
        
        # Get pending applications for owner's properties
        applications = []
        if properties:  # Only try to get applications if we found properties
            try:
                property_ids = [prop['property_id'] for prop in properties]
                for prop_id in property_ids:
                    try:
                        response = application_table.query(
                            IndexName='PropertyStatusIndex',
                            KeyConditionExpression=boto3.dynamodb.conditions.Key('property_id').eq(prop_id) & 
                                                   boto3.dynamodb.conditions.Key('status').eq('pending')
                        )
                        applications.extend(response.get('Items', []))
                    except Exception as app_error:
                        logger.error(f"Application query error for property {prop_id}: {app_error}")
                
                logger.info(f"Found {len(applications)} pending applications")
            except Exception as apps_error:
                logger.error(f"Applications processing error: {apps_error}")
                applications = []
        
        # Get active bookings for owner's properties
        bookings = []
        if properties:  # Only try to get bookings if we found properties
            try:
                for prop_id in property_ids:
                    try:
                        response = booking_table.query(
                            IndexName='PropertyStatusIndex',
                            KeyConditionExpression=boto3.dynamodb.conditions.Key('property_id').eq(prop_id) & 
                                                   boto3.dynamodb.conditions.Key('status').eq('active')
                        )
                        bookings.extend(response.get('Items', []))
                    except Exception as book_error:
                        logger.error(f"Booking query error for property {prop_id}: {book_error}")
                
                logger.info(f"Found {len(bookings)} active bookings")
            except Exception as books_error:
                logger.error(f"Bookings processing error: {books_error}")
                bookings = []
        
        return render_template('owner_dashboard.html', 
                              properties=properties,
                              applications=applications,
                              bookings=bookings)
    
    except Exception as e:
        logger.error(f"Owner dashboard error: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash(f'Error loading dashboard data: {str(e)}', 'danger')
        return render_template('owner_dashboard.html', 
                              properties=[],
                              applications=[],
                              bookings=[])

@app.route('/dashboard/tenant')
@login_required
@role_required(['tenant'])
def tenant_dashboard():
    user_id = session.get('user_id')
    user_name = session.get('user_name', 'Tenant')

    try:
        # --- Bookings: Try query, fall back to scan ---
        try:
            booking_response = booking_table.query(
                IndexName='TenantIdIndex',
                KeyConditionExpression=Key('tenant_id').eq(user_id)
            )
        except Exception as index_error:
            logger.warning(f"Index error when querying bookings: {index_error}, trying scan instead")
            booking_response = booking_table.scan(
                FilterExpression=Attr('tenant_id').eq(user_id)
            )

        bookings = booking_response.get('Items', [])
        active_bookings = [b for b in bookings if b.get('status') == 'active']
        booking_property_ids = {b['property_id'] for b in active_bookings}

        # --- Applications: Try query, fall back to scan ---
        try:
            application_response = application_table.query(
                IndexName='TenantIdIndex',
                KeyConditionExpression=Key('tenant_id').eq(user_id)
            )
        except Exception as index_error:
            logger.warning(f"Index error when querying applications: {index_error}, trying scan instead")
            application_response = application_table.scan(
                FilterExpression=Attr('tenant_id').eq(user_id)
            )

        applications = application_response.get('Items', [])
        pending_applications = [a for a in applications if a.get('status') == 'pending']
        application_property_ids = {a['property_id'] for a in pending_applications}

        # --- Batch get all relevant property details ---
        all_property_ids = list(booking_property_ids.union(application_property_ids))
        property_details_map = {}

        if all_property_ids:
            keys = [{'property_id': pid} for pid in all_property_ids]
            response = dynamodb.batch_get_item(
                RequestItems={
                    property_table.name: {
                        'Keys': keys
                    }
                }
            )
            for item in response['Responses'].get(property_table.name, []):
                property_details_map[item['property_id']] = item

        # Attach property details to bookings and applications
        for b in active_bookings:
            b['property_details'] = property_details_map.get(b['property_id'], {})

        for a in pending_applications:
            a['property_details'] = property_details_map.get(a['property_id'], {})

        # --- Recommended properties (available ones) ---
        property_response = property_table.scan(
            FilterExpression=Attr('status').eq('available'),
            Limit=5
        )
        recommended_properties = property_response.get('Items', [])

        for prop in recommended_properties:
            if 'price' in prop and isinstance(prop['price'], Decimal):
                prop['price'] = float(prop['price'])
            if 'bedrooms' in prop and isinstance(prop['bedrooms'], Decimal):
                prop['bedrooms'] = int(prop['bedrooms'])
            if 'bathrooms' in prop and isinstance(prop['bathrooms'], Decimal):
                prop['bathrooms'] = int(prop['bathrooms'])

        return render_template('tenant_dashboard.html',
                               bookings=active_bookings,
                               applications=pending_applications,
                               recommended_properties=recommended_properties,
                               user_name=user_name)

    except Exception as e:
        logger.error(f"Tenant dashboard error: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash('Error loading dashboard data', 'danger')
        return render_template('tenant_dashboard.html',
                               bookings=[],
                               applications=[],
                               recommended_properties=[],
# --------------------------------------- #
# Property Management Routes
# --------------------------------------- #
@app.route('/properties')
@login_required
def list_properties():
    try:
        # Get filter parameters
        min_price = request.args.get('min_price', 0, type=float)
        max_price = request.args.get('max_price', 1000000, type=float)
        bedrooms = request.args.get('bedrooms')
        location = request.args.get('location', '')
        property_type = request.args.get('property_type', '')
        
        # Debug: Log filter parameters
        logger.info(f"Listing properties with filters: min_price={min_price}, max_price={max_price}, "
                    f"bedrooms={bedrooms}, location={location}, property_type={property_type}")
        
        # Start with basic scan to get all properties
        try:
            scan_response = property_table.scan()
            all_properties = scan_response.get('Items', [])
            logger.info(f"Found {len(all_properties)} total properties in database")
            
            filtered_properties = []
            
            for prop in all_properties:
                # Apply price filter
                price = float(prop.get('price', 0))
                if price < min_price or price > max_price:
                    continue
                
                # Apply bedrooms filter if specified
                if bedrooms and int(prop.get('bedrooms', 0)) != int(bedrooms):
                    continue
                
                # Apply location filter if specified
                if location and location.lower() not in prop.get('location', '').lower():
                    continue
                
                # Apply property type filter if specified
                if property_type and prop.get('property_type') != property_type:
                    continue
                
                # Only show available properties
                if prop.get('status') != 'available':
                    continue
                
                filtered_properties.append(prop)
            
            logger.info(f"After filtering: {len(filtered_properties)} properties")
            
            if filtered_properties:
                logger.info(f"Sample property: {filtered_properties[0]}")
                
            return render_template('properties.html', properties=filtered_properties)
        
        except Exception as scan_error:
            logger.error(f"Error scanning properties: {scan_error}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            flash('Error retrieving property listings', 'danger')
            return render_template('properties.html', properties=[])
        
    except Exception as e:
        logger.error(f"Property listing error: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash(f'Error retrieving property listings: {str(e)}', 'danger')
        return render_template('properties.html', properties=[])

@app.route('/properties/<property_id>')
def view_property(property_id):
    try:
        # Get property details
        response = property_table.get_item(Key={'property_id': property_id})
        
        if 'Item' not in response:
            flash('Property not found', 'danger')
            return redirect(url_for('list_properties'))
        
        property_data = response['Item']
        
        # Get owner details
        owner_response = user_table.get_item(Key={'user_id': property_data['owner_id']})
        owner = owner_response.get('Item', {})
        
        # Check if current user has an active application for this property
        has_application = False
        if 'user_id' in session:
            try:
                app_response = application_table.query(
                    IndexName='TenantPropertyIndex',
                    KeyConditionExpression=boto3.dynamodb.conditions.Key('tenant_id').eq(session['user_id']) & 
                                        boto3.dynamodb.conditions.Key('property_id').eq(property_id)
                )
                has_application = len(app_response.get('Items', [])) > 0
            except Exception as app_error:
                logger.error(f"Error checking applications: {app_error}")
                has_application = False
        
        # Check if templates exist before rendering
        try:
            return render_template('property_detail.html', 
                                property=property_data, 
                                owner=owner,
                                has_application=has_application)
        except Exception as template_error:
            logger.error(f"Template error: {template_error}")
            flash(f'Error loading property template: {str(template_error)}', 'danger')
            return redirect(url_for('list_properties'))
    
    except Exception as e:
        logger.error(f"View property error: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash('Error retrieving property details', 'danger')
        return redirect(url_for('list_properties'))
    
    except Exception as e:
        logger.error(f"View property error: {e}")
        flash('Error retrieving property details', 'danger')
        return redirect(url_for('list_properties'))

# Debug add_property function
from decimal import Decimal

@app.route('/properties/add', methods=['GET', 'POST'])
@role_required(['owner', 'admin'])
def add_property():
    if request.method == 'POST':
        try:
            # Get form data
            title = request.form.get('title')
            description = request.form.get('description')
            property_type = request.form.get('property_type')
            bedrooms = int(request.form.get('bedrooms', 0))
            
            # Convert float values to Decimal for DynamoDB compatibility
            bathrooms = Decimal(str(request.form.get('bathrooms', 0)))
            area = Decimal(str(request.form.get('area', 0)))
            price = Decimal(str(request.form.get('price', 0)))
            
            address = request.form.get('address')
            city = request.form.get('city')
            state = request.form.get('state')
            zipcode = request.form.get('zipcode')
            amenities = request.form.getlist('amenities')
            
            # Debug: Log form data to verify what's being submitted
            logger.info(f"Received form data: {request.form}")
            
            # Process image uploads
            images = []
            if 'images' in request.files:
                image_files = request.files.getlist('images')
                for image in image_files:
                    if image.filename:
                        filename = secure_filename(image.filename)
                        unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                        image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                        image.save(image_path)
                        images.append(f"/static/uploads/{unique_filename}")
            
            # Create property record
            property_id = str(uuid.uuid4())
            owner_id = session.get('user_id')
            
            # Debug: Log current user
            logger.info(f"Current user ID: {owner_id}")
            
            property_data = {
                'property_id': property_id,
                'owner_id': owner_id,
                'title': title,
                'description': description,
                'property_type': property_type,
                'bedrooms': bedrooms,
                'bathrooms': bathrooms,
                'area': area,
                'price': price,
                'address': address,
                'city': city,
                'state': state,
                'zipcode': zipcode,
                'location': f"{city}, {state}",
                'amenities': amenities,
                'images': images,
                'status': 'available',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            # Debug: Log property data before saving
            logger.info(f"Property data to save: {property_data}")
            
            try:
                # Save to DynamoDB
                property_table.put_item(Item=property_data)
                logger.info(f"Property saved successfully with ID: {property_id}")
            except Exception as db_error:
                # Debug: Log DynamoDB errors separately
                logger.error(f"DynamoDB error: {db_error}")
                raise
            
            # Verify property was added by retrieving it
            try:
                verification = property_table.get_item(Key={'property_id': property_id})
                if 'Item' in verification:
                    logger.info("Property verification successful")
                else:
                    logger.error("Property verification failed - item not found")
            except Exception as verify_error:
                logger.error(f"Property verification error: {verify_error}")
            
            flash('Property added successfully', 'success')
            return redirect(url_for('view_property', property_id=property_id))
            
        except Exception as e:
            # Provide more detailed error information
            logger.error(f"Add property error: {e}")
            logger.error(f"Error details: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            flash(f'Error adding property: {str(e)}', 'danger')
            return render_template('add_property.html')
    
    return render_template('add_property.html')

@app.route('/properties/<property_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_property(property_id):
    try:
        # Get property details
        response = property_table.get_item(Key={'property_id': property_id})
        
        if 'Item' not in response:
            flash('Property not found', 'danger')
            return redirect(url_for('list_properties'))
        
        property_data = response['Item']
        
        # Check if user is authorized to edit this property
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        if property_data['owner_id'] != user_id and user_role != 'admin':
            flash('You do not have permission to edit this property', 'danger')
            return redirect(url_for('view_property', property_id=property_id))
        
        if request.method == 'POST':
            try:
                # Update property data
                title = request.form.get('title')
                description = request.form.get('description')
                property_type = request.form.get('property_type')
                bedrooms = int(request.form.get('bedrooms', 0))
                bathrooms = float(request.form.get('bathrooms', 0))
                area = float(request.form.get('area', 0))
                price = float(request.form.get('price', 0))
                address = request.form.get('address')
                city = request.form.get('city')
                state = request.form.get('state')
                zipcode = request.form.get('zipcode')
                amenities = request.form.getlist('amenities')
                status = request.form.get('status', 'available')
                
                # Process new image uploads
                existing_images = property_data.get('images', [])
                
                if 'images' in request.files:
                    image_files = request.files.getlist('images')
                    for image in image_files:
                        if image.filename:
                            filename = secure_filename(image.filename)
                            unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                            image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                            image.save(image_path)
                            existing_images.append(f"/static/uploads/{unique_filename}")
                
                # Handle image deletions
                images_to_keep = request.form.getlist('keep_images')
                updated_images = [img for img in existing_images if img in images_to_keep]
                
                # Update property in DynamoDB
                update_expression = """
                SET title = :title, 
                    description = :description,
                    property_type = :property_type,
                    bedrooms = :bedrooms,
                    bathrooms = :bathrooms,
                    area = :area,
                    price = :price,
                    address = :address,
                    city = :city,
                    state = :state,
                    zipcode = :zipcode,
                    location = :location,
                    amenities = :amenities,
                    images = :images,
                    status = :status,
                    updated_at = :updated_at
                """
                
                expression_attribute_values = {
                    ':title': title,
                    ':description': description,
                    ':property_type': property_type,
                    ':bedrooms': bedrooms,
                    ':bathrooms': bathrooms,
                    ':area': area,
                    ':price': price,
                    ':address': address,
                    ':city': city,
                    ':state': state,
                    ':zipcode': zipcode,
                    ':location': f"{city}, {state}",
                    ':amenities': amenities,
                    ':images': updated_images,
                    ':status': status,
                    ':updated_at': datetime.now().isoformat()
                }
                
                property_table.update_item(
                    Key={'property_id': property_id},
                    UpdateExpression=update_expression,
                    ExpressionAttributeValues=expression_attribute_values
                )
                
                flash('Property updated successfully', 'success')
                return redirect(url_for('view_property', property_id=property_id))
                
            except Exception as e:
                logger.error(f"Edit property error: {e}")
                flash('Error updating property', 'danger')
                return render_template('edit_property.html', property=property_data)
        
        return render_template('edit_property.html', property=property_data)
    
    except Exception as e:
        logger.error(f"Edit property page error: {e}")
        flash('Error retrieving property data', 'danger')
        return redirect(url_for('list_properties'))

@app.route('/properties/<property_id>/delete', methods=['POST'])
@login_required
def delete_property(property_id):
    try:
        # Get property details
        response = property_table.get_item(Key={'property_id': property_id})
        
        if 'Item' not in response:
            flash('Property not found', 'danger')
            return redirect(url_for('list_properties'))
        
        property_data = response['Item']
        
        # Check if user is authorized to delete this property
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        if property_data['owner_id'] != user_id and user_role != 'admin':
            flash('You do not have permission to delete this property', 'danger')
            return redirect(url_for('view_property', property_id=property_id))
        
        # Check for active bookings or applications
        booking_response = booking_table.query(
            IndexName='PropertyStatusIndex',
            KeyConditionExpression=boto3.dynamodb.conditions.Key('property_id').eq(property_id) & 
                                   boto3.dynamodb.conditions.Key('status').eq('active')
        )
        
        if booking_response.get('Items', []):
            flash('Cannot delete property with active bookings', 'danger')
            return redirect(url_for('view_property', property_id=property_id))
        
        # Delete property
        property_table.delete_item(Key={'property_id': property_id})
        
        flash('Property deleted successfully', 'success')
        return redirect(url_for('dashboard'))
    
    except Exception as e:
        logger.error(f"Delete property error: {e}")
        flash('Error deleting property', 'danger')
        return redirect(url_for('view_property', property_id=property_id))

# --------------------------------------- #
# Application Management Routes
# --------------------------------------- #
@app.route('/properties/<property_id>/apply', methods=['GET', 'POST'])
@login_required
def apply_property(property_id):
    if request.method == 'POST':
        try:
            from decimal import Decimal
            
            # Get form data and convert numbers to Decimal
            # IMPORTANT: Convert to string first to maintain precision
            monthly_income = Decimal(str(request.form.get('monthly_income', '0')))
            credit_score = Decimal(str(request.form.get('credit_score', '0')))
            rent_budget = Decimal(str(request.form.get('rent_budget', '0')))
            # Convert any other numeric fields similarly
            
            # Other application data fields...
            move_in_date = request.form.get('move_in_date')
            employment_status = request.form.get('employment_status')
            employment_length = request.form.get('employment_length')
            additional_notes = request.form.get('additional_notes')
            
            # Create application record
            application_id = str(uuid.uuid4())
            tenant_id = session.get('user_id')
            
            # Get property owner's ID for notification purposes
            property_response = property_table.get_item(Key={'property_id': property_id})
            if 'Item' not in property_response:
                flash('Property not found', 'danger')
                return redirect(url_for('list_properties'))
            
            property_data = property_response['Item']
            owner_id = property_data.get('owner_id')
            
            # Use datetime.datetime.now() instead of just datetime.now()
            current_time = datetime.datetime.now().isoformat()
            
            application_data = {
                'application_id': application_id,
                'property_id': property_id,
                'tenant_id': tenant_id,
                'owner_id': owner_id,  # Add owner_id to application data
                'monthly_income': monthly_income,
                'credit_score': credit_score,
                'rent_budget': rent_budget,
                'move_in_date': move_in_date,
                'employment_status': employment_status,
                'employment_length': employment_length,
                'additional_notes': additional_notes,
                'status': 'pending',
                'created_at': current_time
            }
            
            # Save to DynamoDB
            application_table.put_item(Item=application_data)
            
            # Send notification to property owner
            owner_message = f"""
            You have a new application for {property_data.get('title', 'your property')}!
            
            Review it now to:
            1. Check tenant details
            2. Verify income and credit information
            3. Approve or reject the application
            """
            
            # Assuming you have a notification function
            try:
                send_notification(
                    owner_id,
                    'New Property Application',
                    owner_message,
                    {'application_id': application_id}
                )
            except Exception as notify_error:
                logger.error(f"Error sending notification: {notify_error}")
                # Continue with application submission even if notification fails
            
            flash('Application submitted successfully', 'success')
            return redirect(url_for('view_property', property_id=property_id))
            
        except Exception as e:
            logger.error(f"Application error: {e}")
            import traceback
            logger.error(f"Application traceback: {traceback.format_exc()}")
            flash(f'Error submitting application: {str(e)}', 'danger')
            return redirect(url_for('view_property', property_id=property_id))
    
    # GET request handling - show application form
    try:
        # Get property details
        response = property_table.get_item(Key={'property_id': property_id})
        
        if 'Item' not in response:
            flash('Property not found', 'danger')
            return redirect(url_for('list_properties'))
        
        property_data = response['Item']
        
        # Check if user already has an application for this property
        user_id = session.get('user_id')
        
        # Try to query using a different index or consider scan if index doesn't exist
        try:
            # First approach: try with the expected index
            app_response = application_table.query(
                IndexName='TenantPropertyIndex',
                KeyConditionExpression=boto3.dynamodb.conditions.Key('tenant_id').eq(user_id) & 
                                    boto3.dynamodb.conditions.Key('property_id').eq(property_id)
            )
        except Exception as idx_error:
            logger.warning(f"Index error, trying scan instead: {idx_error}")
            # Fallback to scan if index doesn't exist
            app_response = application_table.scan(
                FilterExpression=boto3.dynamodb.conditions.Attr('tenant_id').eq(user_id) & 
                               boto3.dynamodb.conditions.Attr('property_id').eq(property_id)
            )
            
        if app_response.get('Items', []):
            flash('You have already applied for this property', 'warning')
            return redirect(url_for('view_property', property_id=property_id))
        
        # Check if property is still available
        if property_data.get('status') != 'available':
            flash('This property is no longer available for applications', 'warning')
            return redirect(url_for('view_property', property_id=property_id))
        
        return render_template('apply_property.html', property=property_data)
    
    except Exception as e:
        logger.error(f"Application form error: {e}")
        import traceback
        logger.error(f"Application form traceback: {traceback.format_exc()}")
        flash('Error loading application form', 'danger')
        return redirect(url_for('view_property', property_id=property_id))
@app.route('/applications/<application_id>')
@login_required
def view_application(application_id):
    try:
        # Get application details
        response = application_table.get_item(Key={'application_id': application_id})
        
        if 'Item' not in response:
            flash('Application not found', 'danger')
            return redirect(url_for('dashboard'))
        
        application = response['Item']
        
        # Check if user is authorized to view this application
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        if application['tenant_id'] != user_id and application['owner_id'] != user_id and user_role != 'admin':
            flash('You do not have permission to view this application', 'danger')
            return redirect(url_for('dashboard'))
        
        # Get property details
        property_response = property_table.get_item(Key={'property_id': application['property_id']})
        property_data = property_response.get('Item', {})
        
        # Get tenant details
        tenant_response = user_table.get_item(Key={'user_id': application['tenant_id']})
        tenant = tenant_response.get('Item', {})
        
        return render_template('application_detail.html', 
                              application=application,
                              property=property_data,
                              tenant=tenant)
    
    except Exception as e:
        logger.error(f"View application error: {e}")
        flash('Error retrieving application details', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/applications/<application_id>/update', methods=['POST'])
@login_required
def update_application_status(application_id):
    try:
        # Get application details
        response = application_table.get_item(Key={'application_id': application_id})
        
        if 'Item' not in response:
            flash('Application not found', 'danger')
            return redirect(url_for('dashboard'))
        
        application = response['Item']
        
        # Check if user is authorized to update this application
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        if application['owner_id'] != user_id and user_role != 'admin':
            flash('You do not have permission to update this application', 'danger')
            return redirect(url_for('view_application', application_id=application_id))
        
        # Update application status
        new_status = request.form.get('status')
        notes = request.form.get('notes', '')
        
        if new_status not in ['approved', 'rejected']:
            flash('Invalid status update', 'danger')
            return redirect(url_for('view_application', application_id=application_id))
        
        # Update application in DynamoDB
        application_table.update_item(
            Key={'application_id': application_id},
            UpdateExpression="SET #status = :status, owner_notes = :notes, updated_at = :updated_at",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':status': new_status,
                ':notes': notes,
                ':updated_at': datetime.now().isoformat()
            }
        )
        
        # Get property details for notification
        property_response = property_table.get_item(Key={'property_id': application['property_id']})
        property_data = property_response.get('Item', {})
        
        # If approved, create booking
        if new_status == 'approved':
            # Create booking record
            booking_id = str(uuid.uuid4())
            
            start_date = datetime.strptime(application['move_in_date'], '%Y-%m-%d')
            end_date = start_date + timedelta(days=30 * application['duration'])
            
            booking_data = {
                'booking_id': booking_id,
                'property_id': application['property_id'],
                'tenant_id': application['tenant_id'],
                'owner_id': application['owner_id'],
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'monthly_rent': property_data.get('price', 0),
                'status': 'pending_payment',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            # Save booking to DynamoDB
            booking_table.put_item(Item=booking_data)
            
            # Update property status to 'leased'
            property_table.update_item(
                Key={'property_id': application['property_id']},
                UpdateExpression="SET #status = :status, updated_at = :updated_at",
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': 'leased',
                    ':updated_at': datetime.now().isoformat()
                }
            )
            
            # Send notification to tenant
            tenant_message = f"""
            Your application for {property_data.get('title', 'the property')} has been approved!
            
            Next steps:
            1. Complete the payment process
            2. Sign the lease agreement
            3. Arrange for move-in on {application['move_in_date']}
            
            Log in to your account to proceed.
            """
            
            send_notification(
                application['tenant_id'],
                'Application Approved',
                tenant_message,
                {'booking_id': booking_id, 'application_id': application_id}
            )
        else:  # rejected
            # Send notification to tenant
            tenant_message = f"""
            Your application for {property_data.get('title', 'the property')} has been declined.
            
            Notes from the owner: {notes}
            
            Please continue browsing for other available properties.
            """
            
            send_notification(
                application['tenant_id'],
                'Application Status Update',
                tenant_message,
                {'application_id': application_id}
            )
        
        flash(f"Application {new_status} successfully", 'success')
        return redirect(url_for('view_application', application_id=application_id))
    
    except Exception as e:
        logger.error(f"Update application status error: {e}")
        flash('Error updating application status', 'danger')
        return redirect(url_for('view_application', application_id=application_id))

# --------------------------------------- #
# Booking Management Routes
# --------------------------------------- #
@app.route('/bookings/<booking_id>')
@login_required
def view_booking(booking_id):
    try:
        # Get booking details
        response = booking_table.get_item(Key={'booking_id': booking_id})
        
        if 'Item' not in response:
            flash('Booking not found', 'danger')
            return redirect(url_for('dashboard'))
        
        booking = response['Item']
        
        # Check if user is authorized to view this booking
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        if booking['tenant_id'] != user_id and booking['owner_id'] != user_id and user_role != 'admin':
            flash('You do not have permission to view this booking', 'danger')
            return redirect(url_for('dashboard'))
        
        # Get property details
        property_response = property_table.get_item(Key={'property_id': booking['property_id']})
        property_data = property_response.get('Item', {})
        
        # Get tenant details
        tenant_response = user_table.get_item(Key={'user_id': booking['tenant_id']})
        tenant = tenant_response.get('Item', {})
        
        # Get owner details
        owner_response = user_table.get_item(Key={'user_id': booking['owner_id']})
        owner = owner_response.get('Item', {})
        
        return render_template('booking_detail.html', 
                              booking=booking,
                              property=property_data,
                              tenant=tenant,
                              owner=owner)
    
    except Exception as e:
        logger.error(f"View booking error: {e}")
        flash('Error retrieving booking details', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/bookings/<booking_id>/confirm-payment', methods=['POST'])
@role_required(['tenant'])
def confirm_booking_payment(booking_id):
    try:
        # Get booking details
        response = booking_table.get_item(Key={'booking_id': booking_id})
        
        if 'Item' not in response:
            flash('Booking not found', 'danger')
            return redirect(url_for('dashboard'))
        
        booking = response['Item']
        
        # Check if user is authorized
        user_id = session.get('user_id')
        
        if booking['tenant_id'] != user_id:
            flash('You do not have permission to confirm this payment', 'danger')
            return redirect(url_for('dashboard'))
        
        if booking['status'] != 'pending_payment':
            flash('This booking is not in payment pending status', 'warning')
            return redirect(url_for('view_booking', booking_id=booking_id))
        
        # In a real application, you would integrate with a payment gateway here
        # For now, we'll simulate a successful payment
        
        # Update booking status
        booking_table.update_item(
            Key={'booking_id': booking_id},
            UpdateExpression="SET #status = :status, payment_confirmed_at = :payment_time, updated_at = :updated_at",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':status': 'active',
                ':payment_time': datetime.now().isoformat(),
                ':updated_at': datetime.now().isoformat()
            }
        )
        
        # Get property details for notification
        property_response = property_table.get_item(Key={'property_id': booking['property_id']})
        property_data = property_response.get('Item', {})
        
        # Send notification to owner
        owner_message = f"""
        Payment confirmed for your property: {property_data.get('title', 'the property')}
        
        The booking is now active. The tenant will move in on {booking['start_date']}.
        """
        
        send_notification(
            booking['owner_id'],
            'Booking Payment Confirmed',
            owner_message,
            {'booking_id': booking_id}
        )
        
        flash('Payment confirmed successfully. Your booking is now active.', 'success')
        return redirect(url_for('view_booking', booking_id=booking_id))
    
    except Exception as e:
        logger.error(f"Confirm payment error: {e}")
        flash('Error confirming payment', 'danger')
        return redirect(url_for('view_booking', booking_id=booking_id))

@app.route('/bookings/<booking_id>/cancel', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    try:
        # Get booking details
        response = booking_table.get_item(Key={'booking_id': booking_id})
        
        if 'Item' not in response:
            flash('Booking not found', 'danger')
            return redirect(url_for('dashboard'))
        
        booking = response['Item']
        
        # Check if user is authorized
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        if booking['tenant_id'] != user_id and booking['owner_id'] != user_id and user_role != 'admin':
            flash('You do not have permission to cancel this booking', 'danger')
            return redirect(url_for('dashboard'))
        
        if booking['status'] not in ['pending_payment', 'active']:
            flash('This booking cannot be cancelled in its current state', 'warning')
            return redirect(url_for('view_booking', booking_id=booking_id))
        
        # Get reason for cancellation
        cancellation_reason = request.form.get('cancellation_reason', '')
        cancelled_by = 'tenant' if booking['tenant_id'] == user_id else 'owner'
        
        # Update booking status
        booking_table.update_item(
            Key={'booking_id': booking_id},
            UpdateExpression="SET #status = :status, cancellation_reason = :reason, cancelled_by = :by, cancelled_at = :cancel_time, updated_at = :updated_at",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':status': 'cancelled',
                ':reason': cancellation_reason,
                ':by': cancelled_by,
                ':cancel_time': datetime.now().isoformat(),
                ':updated_at': datetime.now().isoformat()
            }
        )
        
        # Update property status back to available
        property_table.update_item(
            Key={'property_id': booking['property_id']},
            UpdateExpression="SET #status = :status, updated_at = :updated_at",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':status': 'available',
                ':updated_at': datetime.now().isoformat()
            }
        )
        
        # Get property details for notification
        property_response = property_table.get_item(Key={'property_id': booking['property_id']})
        property_data = property_response.get('Item', {})
        
        # Send notification to the other party
        notify_user_id = booking['owner_id'] if cancelled_by == 'tenant' else booking['tenant_id']
        notification_message = f"""
        Booking for {property_data.get('title', 'the property')} has been cancelled by the {cancelled_by}.
        
        Reason: {cancellation_reason}
        """
        
        send_notification(
            notify_user_id,
            'Booking Cancelled',
            notification_message,
            {'booking_id': booking_id}
        )
        
        flash('Booking cancelled successfully', 'success')
        return redirect(url_for('dashboard'))
    
    except Exception as e:
        logger.error(f"Cancel booking error: {e}")
        flash('Error cancelling booking', 'danger')
        return redirect(url_for('view_booking', booking_id=booking_id))

# --------------------------------------- #
# Admin Management Routes
# --------------------------------------- #
@app.route('/admin/users')
@role_required(['admin'])
def admin_users():
    try:
        # Get all users
        response = user_table.scan()
        users = response.get('Items', [])
        
        return render_template('admin_users.html', users=users)
    
    except Exception as e:
        logger.error(f"Admin users error: {e}")
        flash('Error retrieving user data', 'danger')
        return render_template('admin_users.html', users=[])

@app.route('/admin/users/<user_id>')
@role_required(['admin'])
def admin_view_user(user_id):
    try:
        # Get user details
        response = user_table.get_item(Key={'user_id': user_id})
        
        if 'Item' not in response:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))
        
        user = response['Item']
        
        # Get user's properties if they're an owner
        properties = []
        if user['role'] == 'owner':
            property_response = property_table.query(
                IndexName='OwnerIndex',
                KeyConditionExpression=boto3.dynamodb.conditions.Key('owner_id').eq(user_id)
            )
            properties = property_response.get('Items', [])
        
        # Get user's bookings if they're a tenant
        bookings = []
        if user['role'] == 'tenant':
            booking_response = booking_table.query(
                IndexName='TenantStatusIndex',
                KeyConditionExpression=boto3.dynamodb.conditions.Key('tenant_id').eq(user_id)
            )
            bookings = booking_response.get('Items', [])
            
            # Get property details for each booking
            for booking in bookings:
                property_response = property_table.get_item(
                    Key={'property_id': booking['property_id']}
                )
                if 'Item' in property_response:
                    booking['property_details'] = property_response['Item']
        
        return render_template('admin_user_detail.html', 
                              user=user,
                              properties=properties,
                              bookings=bookings)
    
    except Exception as e:
        logger.error(f"Admin view user error: {e}")
        flash('Error retrieving user details', 'danger')
        return redirect(url_for('admin_users'))

@app.route('/admin/users/<user_id>/edit', methods=['GET', 'POST'])
@role_required(['admin'])
def admin_edit_user(user_id):
    try:
        # Get user details
        response = user_table.get_item(Key={'user_id': user_id})
        
        if 'Item' not in response:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))
        
        user = response['Item']
        
        if request.method == 'POST':
            # Update user data
            name = request.form.get('name')
            email = request.form.get('email').lower()
            phone = request.form.get('phone')
            role = request.form.get('role')
            status = request.form.get('status')
            
            # Update user in DynamoDB
            update_expression = """
                 SET #name = :name,
                    #email = :email,
                    #phone = :phone,
                    #role = :role,
                    #status = :status,
                    updated_at = :updated_at
                """
            


            
            expression_attribute_names = {
                '#name': 'name',
                '#email': 'email',
                '#phone': 'phone',
                '#role': 'role',
                '#status': 'status'
            }
            
            expression_attribute_values = {
                ':name': name,
                ':email': email,
                ':phone': phone,
                ':role': role,
                ':status': status,
                ':updated_at': datetime.now().isoformat()
            }
            
            user_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression=update_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_attribute_values
            )
            
            flash('User updated successfully', 'success')
            return redirect(url_for('admin_view_user', user_id=user_id))
        
        return render_template('admin_edit_user.html', user=user)
    
    except Exception as e:
        logger.error(f"Admin edit user error: {e}")
        flash('Error updating user', 'danger')
        return redirect(url_for('admin_view_user', user_id=user_id))
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/admin/properties')
@role_required(['admin'])
def admin_properties():
    try:
        # Get all properties
        response = property_table.scan()
        properties = response.get('Items', [])
        
        return render_template('admin_properties.html', properties=properties)
    
    except Exception as e:
        logger.error(f"Admin properties error: {e}")
        flash('Error retrieving property data', 'danger')
        return render_template('admin_properties.html', properties=[])

@app.route('/admin/bookings')
@role_required(['admin'])
def admin_bookings():
    try:
        # Get all bookings
        response = booking_table.scan()
        bookings = response.get('Items', [])
        
        # Get property details for each booking
        for booking in bookings:
            property_response = property_table.get_item(
                Key={'property_id': booking['property_id']}
            )
            if 'Item' in property_response:
                booking['property_details'] = property_response['Item']
        
        return render_template('admin_bookings.html', bookings=bookings)
    
    except Exception as e:
        logger.error(f"Admin bookings error: {e}")
        flash('Error retrieving booking data', 'danger')
        return render_template('admin_bookings.html', bookings=[])

@app.route('/admin/applications')
@role_required(['admin'])
def admin_applications():
    try:
        # Get all applications
        response = application_table.scan()
        applications = response.get('Items', [])
        
        # Get property details for each application
        for application in applications:
            property_response = property_table.get_item(
                Key={'property_id': application['property_id']}
            )
            if 'Item' in property_response:
                application['property_details'] = property_response['Item']
        
        return render_template('admin_applications.html', applications=applications)
    
    except Exception as e:
        logger.error(f"Admin applications error: {e}")
        flash('Error retrieving application data', 'danger')
        return render_template('admin_applications.html', applications=[])

# --------------------------------------- #
# API Routes
# --------------------------------------- #
@app.route('/api/properties')
def api_properties():
    try:
        # Get filter parameters
        min_price = request.args.get('min_price', 0, type=float)
        max_price = request.args.get('max_price', 1000000, type=float)
        bedrooms = request.args.get('bedrooms')
        location = request.args.get('location', '')
        property_type = request.args.get('property_type', '')
        
        # Base scan parameters
        scan_params = {
            'FilterExpression': boto3.dynamodb.conditions.Attr('status').eq('available')
        }
        
        # Add price filter
        scan_params['FilterExpression'] &= boto3.dynamodb.conditions.Attr('price').between(min_price, max_price)
        
        # Add bedrooms filter if specified
        if bedrooms:
            scan_params['FilterExpression'] &= boto3.dynamodb.conditions.Attr('bedrooms').eq(int(bedrooms))
        
        # Add location filter if specified
        if location:
            scan_params['FilterExpression'] &= boto3.dynamodb.conditions.Attr('location').contains(location)
        
        # Add property type filter if specified
        if property_type:
            scan_params['FilterExpression'] &= boto3.dynamodb.conditions.Attr('property_type').eq(property_type)
        
        # Execute the scan
        response = property_table.scan(**scan_params)
        properties = response.get('Items', [])
        
        # Convert Decimal to float for JSON serialization
        for prop in properties:
            if 'price' in prop and isinstance(prop['price'], Decimal):
                prop['price'] = float(prop['price'])
            if 'area' in prop and isinstance(prop['area'], Decimal):
                prop['area'] = float(prop['area'])
        
        return jsonify({
            'success': True,
            'count': len(properties),
            'properties': properties
        })
        
    except Exception as e:
        logger.error(f"API properties error: {e}")
        return jsonify({
            'success': False,
            'message': 'Error retrieving properties',
            'error': str(e)
        }), 500

@app.route('/api/property/<property_id>')
def api_property(property_id):
    try:
        # Get property details
        response = property_table.get_item(Key={'property_id': property_id})
        
        if 'Item' not in response:
            return jsonify({
                'success': False,
                'message': 'Property not found'
            }), 404
        
        property_data = response['Item']
        
        # Convert Decimal to float for JSON serialization
        if 'price' in property_data and isinstance(property_data['price'], Decimal):
            property_data['price'] = float(property_data['price'])
        if 'area' in property_data and isinstance(property_data['area'], Decimal):
            property_data['area'] = float(property_data['area'])
        
        return jsonify({
            'success': True,
            'property': property_data
        })
        
    except Exception as e:
        logger.error(f"API property detail error: {e}")
        return jsonify({
            'success': False,
            'message': 'Error retrieving property details',
            'error': str(e)
        }), 500

@app.route('/api/properties/search')
def api_search_properties():
    try:
        # Get search query
        query = request.args.get('q', '').lower()
        
        if not query or len(query) < 3:
            return jsonify({
                'success': False,
                'message': 'Search query too short'
            }), 400
        
        # Scan properties table
        response = property_table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('status').eq('available') &
                           (boto3.dynamodb.conditions.Attr('title').contains(query) |
                            boto3.dynamodb.conditions.Attr('description').contains(query) |
                            boto3.dynamodb.conditions.Attr('location').contains(query))
        )
        
        properties = response.get('Items', [])
        
        # Convert Decimal to float for JSON serialization
        for prop in properties:
            if 'price' in prop and isinstance(prop['price'], Decimal):
                prop['price'] = float(prop['price'])
            if 'area' in prop and isinstance(prop['area'], Decimal):
                prop['area'] = float(prop['area'])
        
        return jsonify({
            'success': True,
            'count': len(properties),
            'properties': properties
        })
        
    except Exception as e:
        logger.error(f"API property search error: {e}")
        return jsonify({
            'success': False,
            'message': 'Error searching properties',
            'error': str(e)
        }), 500

@app.route('/api/user/bookings')
@login_required
def api_user_bookings():
    user_id = session.get('user_id')
    user_role = session.get('role')
    
    try:
        bookings = []
        
        if user_role == 'tenant':
            # Get tenant's bookings
            response = booking_table.query(
                IndexName='TenantStatusIndex',
                KeyConditionExpression=boto3.dynamodb.conditions.Key('tenant_id').eq(user_id)
            )
            bookings = response.get('Items', [])
        elif user_role == 'owner':
            # Get owner's bookings
            response = booking_table.query(
                IndexName='OwnerStatusIndex',
                KeyConditionExpression=boto3.dynamodb.conditions.Key('owner_id').eq(user_id) 
            )
            bookings = response.get('Items', [])
        
        # Get property details for each booking
        for booking in bookings:
            property_response = property_table.get_item(
                Key={'property_id': booking['property_id']}
            )
            if 'Item' in property_response:
                booking['property_details'] = property_response['Item']
        
        return jsonify({
            'success': True,
            'count': len(bookings),
            'bookings': bookings
        })
        
    except Exception as e:
        logger.error(f"API user bookings error: {e}")
        return jsonify({
            'success': False,
            'message': 'Error retrieving bookings',
            'error': str(e)
        }), 500


# --------------------------------------- #
# Utility Routes
# --------------------------------------- #
@app.route('/health')
def health_check():
    """Health check endpoint for load balancers"""
    try:
        # Check DynamoDB connection
        user_table.scan(Limit=1)
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/sitemap')
def sitemap():
    """Generate a simple sitemap of routes"""
    routes = []
    for rule in app.url_map.iter_rules():
        if "GET" in rule.methods and not rule.arguments and not rule.endpoint.startswith(('api', 'static', 'health')):
            routes.append(rule.endpoint)
    
    return render_template('sitemap.html', routes=routes)

# --------------------------------------- #
# Main Application Entry
# --------------------------------------- #
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    # Create database tables if they don't exist
    try:
        # Check if tables exist, create them if they don't
        existing_tables = boto3.client('dynamodb', region_name=AWS_REGION_NAME).list_tables()['TableNames']
        
        # Create UsersTable if it doesn't exist
        if USERS_TABLE_NAME not in existing_tables:
            logger.info(f"Creating table: {USERS_TABLE_NAME}")
            dynamodb.create_table(
                TableName=USERS_TABLE_NAME,
                KeySchema=[
                    {'AttributeName': 'user_id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'user_id', 'AttributeType': 'S'},
                    {'AttributeName': 'email', 'AttributeType': 'S'}
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'EmailIndex',
                        'KeySchema': [
                            {'AttributeName': 'email', 'KeyType': 'HASH'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
        
        # Create PropertiesTable if it doesn't exist
        if PROPERTIES_TABLE_NAME not in existing_tables:
            logger.info(f"Creating table: {PROPERTIES_TABLE_NAME}")
            dynamodb.create_table(
                TableName=PROPERTIES_TABLE_NAME,
                KeySchema=[
                    {'AttributeName': 'property_id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'property_id', 'AttributeType': 'S'},
                    {'AttributeName': 'owner_id', 'AttributeType': 'S'},
                    {'AttributeName': 'status', 'AttributeType': 'S'}
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'OwnerIndex',
                        'KeySchema': [
                            {'AttributeName': 'owner_id', 'KeyType': 'HASH'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    },
                    {
                        'IndexName': 'StatusIndex',
                        'KeySchema': [
                            {'AttributeName': 'status', 'KeyType': 'HASH'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
        
        # Create ApplicationsTable if it doesn't exist
        if APPLICATIONS_TABLE_NAME not in existing_tables:
            logger.info(f"Creating table: {APPLICATIONS_TABLE_NAME}")
            dynamodb.create_table(
                TableName=APPLICATIONS_TABLE_NAME,
                KeySchema=[
                    {'AttributeName': 'application_id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'application_id', 'AttributeType': 'S'},
                    {'AttributeName': 'tenant_id', 'AttributeType': 'S'},
                    {'AttributeName': 'property_id', 'AttributeType': 'S'},
                    {'AttributeName': 'status', 'AttributeType': 'S'}
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'TenantStatusIndex',
                        'KeySchema': [
                            {'AttributeName': 'tenant_id', 'KeyType': 'HASH'},
                            {'AttributeName': 'status', 'KeyType': 'RANGE'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    },
                    {
                        'IndexName': 'PropertyStatusIndex',
                        'KeySchema': [
                            {'AttributeName': 'property_id', 'KeyType': 'HASH'},
                            {'AttributeName': 'status', 'KeyType': 'RANGE'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    },
                    {
                        'IndexName': 'TenantPropertyIndex',
                        'KeySchema': [
                            {'AttributeName': 'tenant_id', 'KeyType': 'HASH'},
                            {'AttributeName': 'property_id', 'KeyType': 'RANGE'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
        
        # Create BookingsTable if it doesn't exist
        if BOOKINGS_TABLE_NAME not in existing_tables:
            logger.info(f"Creating table: {BOOKINGS_TABLE_NAME}")
            dynamodb.create_table(
                TableName=BOOKINGS_TABLE_NAME,
                KeySchema=[
                    {'AttributeName': 'booking_id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'booking_id', 'AttributeType': 'S'},
                    {'AttributeName': 'tenant_id', 'AttributeType': 'S'},
                    {'AttributeName': 'owner_id', 'AttributeType': 'S'},
                    {'AttributeName': 'property_id', 'AttributeType': 'S'},
                    {'AttributeName': 'status', 'AttributeType': 'S'}
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'TenantStatusIndex',
                        'KeySchema': [
                            {'AttributeName': 'tenant_id', 'KeyType': 'HASH'},
                            {'AttributeName': 'status', 'KeyType': 'RANGE'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    },
                    {
                        'IndexName': 'OwnerStatusIndex',
                        'KeySchema': [
                            {'AttributeName': 'owner_id', 'KeyType': 'HASH'},
                            {'AttributeName': 'status', 'KeyType': 'RANGE'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    },
                    {
                        'IndexName': 'PropertyStatusIndex',
                        'KeySchema': [
                            {'AttributeName': 'property_id', 'KeyType': 'HASH'},
                            {'AttributeName': 'status', 'KeyType': 'RANGE'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
    except Exception as e:
        logger.error(f"Error creating DynamoDB tables: {e}")
    
    # Create admin user if it doesn't exist
    try:
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
        
        # Check if admin user exists
        response = user_table.query(
            IndexName='EmailIndex',
            KeyConditionExpression=boto3.dynamodb.conditions.Key('email').eq(admin_email)
        )
        
        if not response.get('Items'):
            # Create admin user
            admin_id = str(uuid.uuid4())
            hashed_password = hash_password(admin_password).decode('utf-8')
            
            admin_data = {
                'user_id': admin_id,
                'email': admin_email,
                'password': hashed_password,
                'name': 'System Administrator',
                'phone': '0000000000',
                'role': 'admin',
                'email_notifications': True,
                'sms_notifications': False,
                'created_at': datetime.now().isoformat(),
                'status': 'active'
            }
            
            user_table.put_item(Item=admin_data)
            logger.info(f"Admin user created: {admin_email}")
    except Exception as e:
        logger.error(f"Error creating admin user: {e}")
    
    # Run the app
    app.run(host='0.0.0.0', port=port, debug=debug)
