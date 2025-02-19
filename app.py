from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, flash
from pymongo import MongoClient
import bcrypt
import random
import string
from bson.binary import Binary
import os
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from datetime import datetime, timezone, timedelta
from bson import ObjectId
import dropbox
import PyPDF2
import io
import requests
from dropbox.files import WriteMode
from functools import wraps
import certifi
from dropbox import Dropbox
from dropbox.oauth import DropboxOAuth2FlowNoRedirect
import json
import threading
import time
from datetime import datetime, timezone
from bson import ObjectId
from bson.errors import InvalidId

import pandas as pd
import numpy as np

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

# Get configuration from environment variables
MONGO_URI = os.getenv('MONGO_URI')
DROPBOX_APP_KEY = os.getenv('DROPBOX_APP_KEY')
DROPBOX_APP_SECRET = os.getenv('DROPBOX_APP_SECRET')
DROPBOX_REFRESH_TOKEN = os.getenv('DROPBOX_REFRESH_TOKEN')
CALENDLY_CLIENT_ID = os.getenv('CALENDLY_CLIENT_ID')
CALENDLY_CLIENT_SECRET = os.getenv('CALENDLY_CLIENT_SECRET')
CALENDLY_WEBHOOK_SIGNING_KEY = os.getenv('CALENDLY_WEBHOOK_SIGNING_KEY')

# Configure MongoDB client
client = MongoClient(MONGO_URI)

db = client['wcm_dashboard']
employees = db['employees']
onboarding_collection = db['onboarding']  # Renamed to avoid conflict
room_bookings = db['room_bookings']
request_closing = db['request_closing']  # New collection for closing requests
pda_collection = db['pda']  # New collection for PDA forms
pda_submissions = db['pda_submissions']  # New collection for PDA submissions
wcm = db['wcm']
tickets = db['tickets']  # New collection for tickets
closing_requests = db['closing_requests']  # New collection for closing requests
dropbox_files = db['dropbox_files']  # New collection for dropbox files
form_statuses = db['form_statuses']  # New collection for form statuses
documents_collection = db['documents']  # Add documents collection
cda = db['cda']  # New collection for CDA submissions
login_requests = db['login_requests']  # New collection for login requests

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'xls', 'xlsx', 'txt'}

TICKET_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, 'tickets')
if not os.path.exists(TICKET_UPLOAD_FOLDER):
    os.makedirs(TICKET_UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Role-based access control decorator
def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            user = employees.find_one({'_id': ObjectId(session['user_id'])})
            if not user or user.get('role') not in allowed_roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Generate and insert required employee records
def insert_sample_employees():
    """Insert or update required employees and admin users in the database"""
    
    # Check if employees already exist
    if employees.count_documents({}) > 0 and wcm.count_documents({}) > 0:
        print("Employees and admin users already exist. Updating passwords...")
        
        # Update Sarah's employee password
        sarah_password = '707311sarah'
        sarah_hashed = bcrypt.hashpw(sarah_password.encode('utf-8'), bcrypt.gensalt())
        employees.update_one(
            {'email': 'sarah@wcmlending.net'},
            {'$set': {
                'password': sarah_hashed,
                'role': 'user'
            }}
        )
        
        # Update Sarah's admin password
        sarah_admin_password = 'sarahadmin707311'
        sarah_admin_hashed = bcrypt.hashpw(sarah_admin_password.encode('utf-8'), bcrypt.gensalt())
        wcm.update_one(
            {'email': 'sarah@wcmlending.net'},
            {'$set': {
                'password': sarah_admin_hashed,
                'role': 'admin',
                'name': 'Sarah Porter',
                'is_admin': True
            }},
            upsert=True
        )
        
        # Update Daniel's employee password
        daniel_password = '707311daniel'
        daniel_hashed = bcrypt.hashpw(daniel_password.encode('utf-8'), bcrypt.gensalt())
        employees.update_one(
            {'email': 'daniel@wcmlending.net'},
            {'$set': {
                'password': daniel_hashed,
                'role': 'user'
            }}
        )
        
        # Update Daniel's admin password
        daniel_admin_password = 'danieladmin707311'
        daniel_admin_hashed = bcrypt.hashpw(daniel_admin_password.encode('utf-8'), bcrypt.gensalt())
        wcm.update_one(
            {'email': 'daniel@wcmlending.net'},
            {'$set': {
                'password': daniel_admin_hashed,
                'role': 'admin',
                'name': 'Daniel Contreras',
                'is_admin': True
            }},
            upsert=True
        )
        
        # Update existing admin passwords if needed
        wcm.update_one(
            {'email': 'compliance@wcmlending.net'},
            {'$set': {
                'password': bcrypt.hashpw('wcmcompliance707'.encode('utf-8'), bcrypt.gensalt()),
                'role': 'admin'
            }}
        )
        
        wcm.update_one(
            {'email': 'admin@wcmlending.net'},
            {'$set': {
                'password': bcrypt.hashpw('wcmadmin707'.encode('utf-8'), bcrypt.gensalt()),
                'role': 'admin'
            }}
        )
        
        print("Employee and admin passwords updated successfully")
        return
    
    print("No existing employees found. Creating new employees and admin users...")
    
    # Clear existing employees and admin users
    employees.delete_many({})
    wcm.delete_many({})
    
    # Insert employees
    employee_list = [
        {
            'first_name': 'Sarah',
            'last_name': 'Porter',
            'name': 'Sarah Porter',
            'email': 'sarah@wcmlending.net',
            'role': 'user',
            'created_at': datetime.now(timezone.utc)
        },
        {
            'first_name': 'Daniel',
            'last_name': 'Contreras',
            'name': 'Daniel Contreras',
            'email': 'daniel@wcmlending.net',
            'role': 'user',
            'created_at': datetime.now(timezone.utc)
        },
        {
            'first_name': 'WCM',
            'last_name': 'Compliance',
            'name': 'WCM Compliance',
            'email': 'compliance@wcmlending.net',
            'role': 'user',
            'created_at': datetime.now(timezone.utc)
        }
    ]
    
    # Insert admin users
    admin_list = [
        {
            'name': 'Sarah Porter',
            'email': 'sarah@wcmlending.net',
            'role': 'admin',
            'is_admin': True,
            'created_at': datetime.now(timezone.utc)
        },
        {
            'name': 'Daniel Contreras',
            'email': 'daniel@wcmlending.net',
            'role': 'admin',
            'is_admin': True,
            'created_at': datetime.now(timezone.utc)
        },
        {
            'name': 'WCM Compliance',
            'email': 'compliance@wcmlending.net',
            'role': 'admin',
            'is_admin': True,
            'created_at': datetime.now(timezone.utc)
        },
        {
            'name': 'WCM Admin',
            'email': 'admin@wcmlending.net',
            'role': 'admin',
            'is_admin': True,
            'created_at': datetime.now(timezone.utc)
        }
    ]
    
    # Set passwords and insert employees
    for employee in employee_list:
        if employee['email'] == 'sarah@wcmlending.net':
            password = '707311sarah'
        elif employee['email'] == 'daniel@wcmlending.net':
            password = '707311daniel'
        else:
            password = '707311compliance'
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        employee['password'] = hashed_password
        employees.insert_one(employee)
    
    # Set passwords and insert admin users
    for admin in admin_list:
        if admin['email'] == 'sarah@wcmlending.net':
            password = 'sarahadmin707311'
        elif admin['email'] == 'daniel@wcmlending.net':
            password = 'danieladmin707311'
        elif admin['email'] == 'compliance@wcmlending.net':
            password = 'wcmcompliance707'
        else:
            password = 'wcmadmin707'
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        admin['password'] = hashed_password
        wcm.insert_one(admin)
    
    print("Employees and admin users added successfully")

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/onboarding')
def onboarding():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('onboarding.html')

@app.route('/closing-request')
def closing_request():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    # Get list of processors for the dropdown
    processors = list(employees.find({'role': 'Processor'}))
    
    # Get employee name
    user_id = session['user_id']
    employee = employees.find_one({'_id': ObjectId(user_id)})
    employee_name = employee.get('name', '') if employee else ''
    
    user = employees.find_one({'_id': ObjectId(session['user_id'])})
    return render_template('closing_request.html', processors=processors, user=user, employee_name=employee_name)

@app.route('/pda', methods=['GET'])
def pda():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.args.get('view') == 'submissions':
        try:
            submissions = list(pda_submissions.find(
                {'user_id': session['user_id']}
            ).sort('created_at', -1))
            
            # Format submissions for display
            for sub in submissions:
                try:
                    # Format the submission date
                    created_at = sub.get('created_at')
                    if isinstance(created_at, datetime):
                        sub['submission_date'] = created_at.strftime('%Y-%m-%d %I:%M %p')
                    else:
                        sub['submission_date'] = 'N/A'
                    
                    # Structure the data based on form sections
                    answers = sub.get('answers', {})
                    sub['borrower_info'] = {
                        'name': answers.get('borrowerName', 'N/A'),
                        'loan_officer': answers.get('loanOfficer', 'N/A'),
                        'complete_drive': answers.get('completeDrive', 'N/A'),
                        'lender_name': answers.get('lenderName', 'N/A')
                    }
                    
                    sub['processor_info'] = {
                        'name': answers.get('processorName', 'N/A'),
                        'phone': answers.get('processorPhone', 'N/A'),
                        'email': answers.get('processorEmail', 'N/A')
                    }
                    
                    sub['escrow_info'] = {
                        'file_number': answers.get('escrowFileNumber', 'N/A'),
                        'company_name': answers.get('escrowCompanyName', 'N/A'),
                        'email': answers.get('escrowEmail', 'N/A'),
                        'phone': answers.get('escrowPhone', 'N/A')
                    }
                    
                    sub['title_info'] = {
                        'file_number': answers.get('titleFileNumber', 'N/A'),
                        'company_name': answers.get('titleCompanyName', 'N/A'),
                        'email': answers.get('titleEmail', 'N/A'),
                        'phone': answers.get('titlePhone', 'N/A')
                    }
                    
                    # Format payment info with proper currency formatting
                    try:
                        payout_amount = float(answers.get('payoutAmount', 0))
                        total_payout = float(answers.get('totalPayout', 0))
                    except (ValueError, TypeError):
                        payout_amount = 0
                        total_payout = 0
                        
                    sub['payment_info'] = {
                        'payout_amount': "${:,.2f}".format(payout_amount),
                        'payee_name': answers.get('payeeName', 'N/A'),
                        'total_payout': "${:,.2f}".format(total_payout)
                    }
                except Exception as e:
                    print(f"Error formatting submission {sub.get('_id')}: {str(e)}")
                    continue
            
            return render_template('pda_submissions.html', submissions=submissions)
        except Exception as e:
            print(f"Error retrieving PDA submissions: {str(e)}")
            return render_template('pda_submissions.html', submissions=[])
            
    return render_template('pda.html')

@app.route('/submit-pda', methods=['POST'])
def submit_pda():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    try:
        data = request.get_json()
        
        # Get user details from session
        user_id = session['user_id']
        user = employees.find_one({'_id': ObjectId(user_id)})
        
        submission = {
            'user_id': user_id,
            'user_name': user.get('name', 'Unknown'),
            'email': user.get('email', ''),
            'answers': data,
            'status': 'pending',
            'created_at': datetime.now(timezone.utc),
            'updated_at': datetime.now(timezone.utc)
        }
        
        result = pda_submissions.insert_one(submission)
        
        if result.inserted_id:
            return jsonify({'success': True, 'message': 'PDA form submitted successfully'})
        return jsonify({'success': False, 'message': 'Failed to submit PDA form'})
        
    except Exception as e:
        print(f"Error submitting PDA form: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while submitting the form'})

@app.route('/faq')
def faq():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('faq.html')

@app.route('/resources')
def resources():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('resources.html')

# Calendly configuration
# CALENDLY_CLIENT_ID = 'hYG8lurZirNg73ep6lL_DQ3PvjX7k88Av1AcbAdulTQ'
# CALENDLY_CLIENT_SECRET = 'w2U3xqVWktR5QDAbERo8wCiofoL3B5vJ7fyQSdLm_9w'
# CALENDLY_WEBHOOK_SIGNING_KEY = 'Ekq_qJpzuwWttLaDN_04tN_HL3n3yHnHbs6wqh2Uae4'

# Initialize Calendly OAuth
def get_calendly_access_token():
    auth_url = 'https://auth.calendly.com/oauth/token'
    auth_data = {
        'grant_type': 'client_credentials',
        'client_id': CALENDLY_CLIENT_ID,
        'client_secret': CALENDLY_CLIENT_SECRET
    }
    response = requests.post(auth_url, data=auth_data)
    if response.status_code == 200:
        return response.json().get('access_token')
    return None

CALENDLY_ROOMS = {
    'upstairs': {
        'name': 'Main Conference Room',
        'url': 'https://calendly.com/wcmupstairs'
    },
    'downstairs': {
        'name': 'Downstairs Conference Room',
        'url': 'https://calendly.com/wcmdownstairs'
    }
}

@app.route('/room_scheduling')
def room_scheduling():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('room_scheduling.html', rooms=CALENDLY_ROOMS)

@app.route('/api/get_room_bookings/<room_id>')
def get_room_bookings(room_id):
    if room_id not in CALENDLY_ROOMS:
        return jsonify({'error': 'Invalid room ID'}), 404
        
    # Here you would typically fetch the room's bookings from Calendly's API
    # For now, we'll return a success message
    return jsonify({
        'success': True,
        'room': CALENDLY_ROOMS[room_id]
    })

# Optional: Webhook endpoint for Calendly events
@app.route('/calendly-webhook', methods=['POST'])
def calendly_webhook():
    try:
        data = request.json
        
        # Verify webhook with signing key
        signature = request.headers.get('Calendly-Webhook-Signature')
        if not signature:
            return jsonify({'error': 'Missing webhook signature'}), 401
            
        # Get access token
        access_token = get_calendly_access_token()
        if not access_token:
            return jsonify({'error': 'Failed to get Calendly access token'}), 500
            
        # Add headers for Calendly API requests
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        # Handle different event types
        event_type = data.get('event')
        
        if event_type == 'invitee.created':
            # New booking created
            booking_data = {
                'event_id': data['payload']['event']['uuid'],
                'user_id': session.get('user_id'),
                'start_time': data['payload']['event']['start_time'],
                'end_time': data['payload']['event']['end_time'],
                'created_at': datetime.now(timezone.utc)
            }
            
            # Verify event details with Calendly API
            event_url = f"https://api.calendly.com/scheduled_events/{booking_data['event_id']}"
            response = requests.get(event_url, headers=headers)
            
            if response.status_code == 200:
                # Store booking in database
                room_bookings.insert_one(booking_data)
            else:
                return jsonify({'error': 'Failed to verify event with Calendly API'}), 400
            
        elif event_type == 'invitee.canceled':
            # Booking canceled
            event_id = data['payload']['event']['uuid']
            room_bookings.delete_one({'event_id': event_id})
        
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        print(f"Error processing Calendly webhook: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/create-ticket')
def create_ticket():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('ticket.html')

@app.route('/tickets')
def view_tickets():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    status_filter = request.args.get('status', 'all')
    
    # Build query based on status filter
    query = {'user_id': session['user_id']}
    if status_filter != 'all':
        query['status'] = status_filter

    # Get tickets with filter
    tickets_list = list(tickets.find(query).sort('created_at', -1))
    return render_template('tickets.html', tickets=tickets_list)

@app.route('/ai-chat')
def ai_chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('ai_chat.html')

@app.route('/calendar')
def calendar():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('calendar.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400
    
    # First check in wcm collection for admin credentials
    admin_user = wcm.find_one({'email': email})
    if admin_user and bcrypt.checkpw(password.encode('utf-8'), admin_user['password']):
        session['user_id'] = str(admin_user['_id'])
        session['email'] = admin_user['email']
        session['name'] = admin_user.get('name', 'User')
        session['is_admin'] = True
        session['role'] = 'admin'
        return jsonify({'message': 'Login successful', 'redirect': '/admin/dashboard'}), 200
    
    # If not admin, check employee credentials
    employee = employees.find_one({'email': email})
    if employee and bcrypt.checkpw(password.encode('utf-8'), employee['password']):
        session['user_id'] = str(employee['_id'])
        session['email'] = employee['email']
        session['name'] = employee.get('name', 'User')
        session['is_admin'] = False
        session['role'] = 'user'
        return jsonify({'message': 'Login successful', 'redirect': '/home'}), 200
    
    return jsonify({'message': 'Invalid email or password'}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/closing-form')
def closing_form():
    # Redirect to demo form link
    return redirect('https://forms.google.com')

@app.route('/upload-documents', methods=['POST'])
def upload_documents():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        # Store file info in MongoDB
        with open(file_path, 'rb') as f:
            file_data = Binary(f.read())
        
        file_id = request_closing.insert_one({
            'filename': filename,
            'file_data': file_data,
            'user_id': session['user_id'],
            'upload_date': datetime.now(timezone.utc),
            'status': 'uploaded'
        }).inserted_id

        # Remove the temporary file
        os.remove(file_path)
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file_id': str(file_id)
        }), 200
    
    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/submit-closing-request', methods=['POST'])
def submit_closing_request():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    files = data.get('files', [])

    # Update the status of all uploaded files to 'submitted'
    request_closing.update_many(
        {
            'user_id': session['user_id'],
            'status': 'uploaded',
            'filename': {'$in': files}
        },
        {'$set': {'status': 'submitted'}}
    )

    return jsonify({'message': 'Request submitted successfully'}), 200

@app.route('/request-review')
def request_review():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Get the user's submitted files
    files = list(request_closing.find({
        'user_id': session['user_id'],
        'status': 'submitted'
    }))

    return render_template('request_review.html', 
                         uploaded_files=files,
                         submission_time=datetime.now(timezone.utc).strftime('%B %d, %Y at %I:%M %p'))

@app.route('/my-bookings')
def my_bookings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get user's bookings
    bookings = list(room_bookings.find({'user_id': session['user_id']}).sort('date', -1))
    
    # Add is_upcoming flag to each booking and format time
    current_time = datetime.utcnow()
    for booking in bookings:
        # Format date
        booking_date = datetime.strptime(booking['date'], '%Y-%m-%d')
        booking['date'] = booking_date.strftime('%B %d, %Y')
        
        # Format start and end time
        start_time = datetime.strptime(booking['startTime'], '%H:%M')
        end_time = datetime.strptime(booking['endTime'], '%H:%M')
        booking['startTime'] = start_time.strftime('%I:%M %p')
        booking['endTime'] = end_time.strftime('%I:%M %p')
        
        # Check if booking is upcoming
        booking_datetime = datetime.combine(
            booking_date.date(),
            end_time.time()
        )
        booking['is_upcoming'] = booking_datetime > current_time
    
    return render_template('my_bookings.html', bookings=bookings)

@app.route('/api/tickets', methods=['POST'])
def create_ticket_api():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        # Get form data
        subject = request.form.get('subject')
        description = request.form.get('description')
        category = request.form.get('category')
        priority = request.form.get('priority')

        # Validate required fields
        if not all([subject, description, category, priority]):
            return jsonify({'error': 'All fields are required'}), 400

        # Handle file uploads
        uploaded_files = []
        if 'attachments' in request.files:
            files = request.files.getlist('attachments')
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    # Create user-specific directory
                    user_upload_dir = os.path.join(TICKET_UPLOAD_FOLDER, str(session['user_id']))
                    if not os.path.exists(user_upload_dir):
                        os.makedirs(user_upload_dir)
                    
                    # Save file
                    file_path = os.path.join(user_upload_dir, filename)
                    file.save(file_path)
                    
                    # Store file info
                    uploaded_files.append({
                        'filename': filename,
                        'path': file_path,
                        'uploaded_at': datetime.now(timezone.utc)
                    })

        # Create ticket document
        current_time = datetime.now(timezone.utc)
        ticket = {
            'subject': subject,
            'description': description,
            'category': category,
            'priority': priority,
            'status': 'open',
            'created_at': current_time,
            'updated_at': current_time,
            'user_id': session['user_id'],
            'attachments': uploaded_files
        }
        
        # Insert into database
        result = tickets.insert_one(ticket)
        
        if result.inserted_id:
            return jsonify({'success': True, 'ticket_id': str(result.inserted_id)}), 201
        else:
            return jsonify({'error': 'Failed to create ticket'}), 500
            
    except Exception as e:
        print(f"Error creating ticket: {str(e)}")
        return jsonify({'error': 'An error occurred while creating the ticket'}), 500

@app.route('/download/ticket/<ticket_id>/<path:file_name>')
def download_attachment(ticket_id, file_name):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        # Get ticket to verify ownership and get file path
        ticket = tickets.find_one({
            '_id': ObjectId(ticket_id),
            'user_id': session['user_id']
        })
        
        if not ticket:
            return "Ticket not found", 404
            
        # Find the attachment
        attachment = next(
            (att for att in ticket['attachments'] if att['filename'] == file_name),
            None
        )
        
        if not attachment:
            return "File not found", 404
            
        # Return the file
        return send_file(
            attachment['path'],
            as_attachment=True,
            download_name=file_name
        )
        
    except Exception as e:
        print(f"Error downloading file: {str(e)}")
        return "Error downloading file", 500

# Dropbox configuration
DROPBOX_APP_KEY = 'mk8crgaubpcp4gp'
DROPBOX_APP_SECRET = '69ucrxiqpjpniri'
DROPBOX_REFRESH_TOKEN = 'ovsWQSs-_8oAAAAAAAAAAUbJceToE4mXBzaoks_GAtj7bo6GnKkPVQeNbeBsyEy9'

# Initialize global dbx variable at module level
dbx = None

def init_dropbox_client():
    """Initialize the global Dropbox client"""
    global dbx
    try:
        dbx = dropbox.Dropbox(
            oauth2_refresh_token=DROPBOX_REFRESH_TOKEN,
            app_key=DROPBOX_APP_KEY,
            app_secret=DROPBOX_APP_SECRET
        )
        print("Dropbox client initialized successfully")
        return True
    except Exception as e:
        print(f"Error initializing Dropbox client: {e}")
        return False

# Initialize Dropbox client when app starts
init_dropbox_client()

def get_dropbox_client():
    """Get the global Dropbox client, reinitialize if needed"""
    global dbx
    if dbx is None:
        init_dropbox_client()
    return dbx

@app.route('/api/upload_document_api', methods=['POST'])
def upload_document_api():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    try:
        global dbx
        if dbx is None:
            init_dropbox_client()
        
        if dbx is not None:
            file = request.files['file']
            document_type = request.form.get('document_type', '')
            
            if not file:
                return jsonify({'success': False, 'error': 'No file uploaded'})
                
            if file.filename == '':
                return jsonify({'success': False, 'error': 'No file selected'})

            # Get employee name from session
            user_id = session['user_id']
            employee = employees.find_one({'_id': ObjectId(user_id)})
            if not employee:
                return jsonify({'success': False, 'error': 'Employee not found'})

            # Sanitize employee name for path
            employee_name = secure_filename(employee.get('name', 'unnamed'))
            
            # Create timestamp for unique filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{secure_filename(file.filename)}"
            
            # Construct Dropbox path with correct structure
            if document_type.lower() in ['w9', 'id']:
                dropbox_path = f"/WCM Dashboard/Onboarding/{employee_name}/{document_type}/{filename}"
            else:
                dropbox_path = f"/WCM Dashboard/Closing Requests/{employee_name}/{document_type}/{filename}"
            
            dropbox_path = dropbox_path.replace('//', '/')
            
            try:
                # Create necessary folders
                folder_path = '/'.join(dropbox_path.split('/')[:-1])
                dbx.files_create_folder_v2(folder_path)
                
                # Upload file
                file_content = file.read()
                upload_result = dbx.files_upload(
                    file_content,
                    dropbox_path,
                    mode=WriteMode.overwrite
                )
                
                print(f"File uploaded successfully to: {upload_result.path_display}")

                return jsonify({
                    'success': True,
                    'message': 'File uploaded successfully',
                    'path': upload_result.path_display
                })

            except dropbox.exceptions.AuthError:
                print("Dropbox authentication failed")
                return jsonify({
                    'success': False,
                    'error': 'Dropbox authentication failed'
                }), 401
            except dropbox.exceptions.ApiError as e:
                print(f"Dropbox API error: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': f'Dropbox API error: {str(e)}'
                }), 500
            except Exception as e:
                print(f"Upload error: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': f'Upload failed: {str(e)}'
                }), 500

    except Exception as e:
        print(f"General error in upload_document_api: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'An unexpected error occurred: {str(e)}'
        }), 500

@app.route('/api/submit_closing_documents', methods=['POST'])
def submit_closing_documents():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'User not logged in'}), 401

        user = employees.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        document_statuses = request.json.get('documentStatuses')
        if not document_statuses:
            return jsonify({'error': 'No document statuses provided'}), 400

        # Validate required documents
        required_documents = [
            'approvalLetter', 'creditReport', 'leReport', 'borrowerAuth',
            'borrowerConditions', 'escrow', 'initialDisclosures', 'cdUpdatedDocuments',
            'borrowersIdentification', 'ss89'
        ]

        for doc in required_documents:
            if not document_statuses.get(doc):
                return jsonify({'error': f'Required document {doc} is missing'}), 400

        # Validate optional documents (must be either uploaded or marked as N/A)
        optional_documents = [
            'appraisalLetter', 'inspections', 'income', 'assets', 'letterExplanation'
        ]

        for doc in optional_documents:
            status = document_statuses.get(doc, {})
            if not isinstance(status, dict) or not (status.get('uploaded') or status.get('na')):
                return jsonify({'error': f'Optional document {doc} must be either uploaded or marked as N/A'}), 400

        # Create a new closing documents submission record
        submission = {
            'user_id': ObjectId(user_id),
            'employee_name': f"{user['first_name']} {user['last_name']}",
            'document_statuses': document_statuses,
            'submitted_at': datetime.now(timezone.utc),
            'status': 'submitted'
        }

        # Insert the submission into MongoDB
        result = request_closing.insert_one(submission)

        # Update the form status in form_statuses collection
        form_statuses.update_one(
            {'user_id': ObjectId(user_id)},
            {
                '$set': {
                    'closing_documents_submitted': True,
                    'closing_documents_submission_id': result.inserted_id,
                    'closing_documents_submitted_at': datetime.now(timezone.utc)
                }
            },
            upsert=True
        )

        # Send notification email to admin
        try:
            admin_email = 'admin@example.com'  # Replace with actual admin email
            subject = f'New Closing Documents Submission - {user["first_name"]} {user["last_name"]}'
            body = f"""
            A new closing documents submission has been received.
            
            Employee: {user['first_name']} {user["last_name"]}
            Submission ID: {str(result.inserted_id)}
            Submitted At: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
            
            Please review the documents in the admin portal.
            """
            
            send_email(admin_email, subject, body)
        except Exception as e:
            # Log email error but don't fail the submission
            print(f"Failed to send notification email: {str(e)}")

        return jsonify({
            'success': True,
            'message': 'Documents submitted successfully',
            'submission_id': str(result.inserted_id)
        })

    except Exception as e:
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@app.route('/api/mark_form_complete', methods=['POST'])
def mark_form_complete():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    user = employees.find_one({'_id': ObjectId(session['user_id'])})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    try:
        form_status = {
            'completed': True,
            'completedBy': f"{user.get('first_name', '')} {user.get('last_name', '')}",
            'completedDate': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'completedById': str(user['_id'])
        }
        
        # Store the form status in MongoDB
        form_statuses = db.form_statuses
        form_statuses.update_one(
            {'type': 'closing_form'},
            {'$set': form_status},
            upsert=True
        )
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/form_status')
def get_form_status():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    try:
        form_statuses = db.form_statuses
        status = form_statuses.find_one({'type': 'closing_form'})
        
        if status:
            return jsonify({
                'completed': status.get('completed', False),
                'completedBy': status.get('completedBy', ''),
                'completedDate': status.get('completedDate', '')
            })
        else:
            return jsonify({'completed': False})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/invite_processor_for_documents', methods=['POST'])
@role_required(['Loan Officer'])
def invite_processor_for_documents():
    try:
        data = request.get_json()
        processor_id = data.get('processorId')
        additional_message = data.get('additionalMessage', '')
        
        if not processor_id:
            return jsonify({'error': 'Processor ID is required'}), 400
        
        # Get processor details
        processor = employees.find_one({'_id': ObjectId(processor_id)})
        if not processor:
            return jsonify({'error': 'Processor not found'}), 404
        
        # Get loan officer details
        loan_officer = employees.find_one({'_id': ObjectId(session['user_id'])})
        
        # Create document upload invitation record
        invitation = {
            'loan_officer_id': str(loan_officer['_id']),
            'processor_id': processor_id,
            'type': 'document_upload',
            'status': 'pending',
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        
        # Store invitation in database
        db.processor_invitations.insert_one(invitation)
        
        # Prepare email content
        email_body = f"""
        Hello {processor['first_name']},
        
        {loan_officer['first_name']} {loan_officer['last_name']} has requested your assistance with document upload for a closing request.
        
        Required Documents:
        - Closing Disclosure
        - Note
        - Deed of Trust
        - Other Supporting Documents
        
        Additional Message from {loan_officer['first_name']}:
        {additional_message if additional_message else 'No additional message provided.'}
        
        Please log in to the dashboard to upload the required documents.
        
        Best regards,
        WCM Team
        """
        
        # Send email notification
        msg = Message(
            subject=f'Document Upload Request - {loan_officer["first_name"]} {loan_officer["last_name"]}',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[processor['email']],
            body=email_body
        )
        mail.send(msg)
        
        return jsonify({
            'success': True,
            'message': f'Document upload invitation sent to {processor["first_name"]} {processor["last_name"]}'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/get_processors')
def get_processors():
    try:
        processor_list = list(employees.find({'role': 'Processor'}, {'_id': 1, 'first_name': 1, 'last_name': 1}))
        processors = [{
            'id': str(p['_id']),
            'name': f"{p['first_name']} {p['last_name']}"
        } for p in processor_list]
        return jsonify({'processors': processors})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/invite_processor', methods=['POST'])
def invite_processor():
    try:
        data = request.get_json()
        processor_id = data.get('processorId')
        additional_message = data.get('additionalMessage', '')
        
        if not processor_id:
            return jsonify({'error': 'Processor ID is required'}), 400
        
        # Get processor details
        processor = employees.find_one({'_id': ObjectId(processor_id)})
        if not processor:
            return jsonify({'error': 'Processor not found'}), 404
        
        # Get loan officer details
        loan_officer = employees.find_one({'_id': ObjectId(session['user_id'])})
        
        # Create invitation record
        invitation = {
            'loan_officer_id': str(loan_officer['_id']),
            'processor_id': processor_id,
            'status': 'pending',
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        
        # Store invitation in database
        db.processor_invitations.insert_one(invitation)
        
        # Prepare email content
        email_body = f"""
        Hello {processor['first_name']},
        
        {loan_officer['first_name']} {loan_officer['last_name']} has invited you to assist with a closing request.
        
        Additional Message from {loan_officer['first_name']}:
        {additional_message if additional_message else 'No additional message provided.'}
        
        Please log in to the dashboard to view and process this request.
        
        Best regards,
        WCM Team
        """
        
        # Send email notification
        msg = Message(
            subject=f'Closing Request Assistance - {loan_officer["first_name"]} {loan_officer["last_name"]}',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[processor['email']],
            body=email_body
        )
        mail.send(msg)
        
        return jsonify({
            'success': True,
            'message': f'Invitation sent to {processor["first_name"]} {processor["last_name"]}'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/assign_processor', methods=['POST'])
def assign_processor():
    try:
        data = request.get_json()
        processor_id = data.get('processorId')
        
        if not processor_id:
            return jsonify({'error': 'Processor ID is required'}), 400
            
        processor = employees.find_one({'_id': ObjectId(processor_id)})
        if not processor:
            return jsonify({'error': 'Processor not found'}), 404
            
        loan_officer = employees.find_one({'_id': ObjectId(session['user_id'])})
        
        # Create closing request
        closing_request = {
            'loan_officer_id': session['user_id'],
            'processor_id': processor_id,
            'status': 'pending_documents',
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        
        result = closing_requests.insert_one(closing_request)
        
        # Send email notification
        send_email(
            to_email=processor['email'],
            subject='Document Upload Request',
            body=f"""
            Hello {processor['first_name']},
            
            {loan_officer['first_name']} {loan_officer['last_name']} has requested your assistance with document upload for a closing request.
            
            Please log in to the dashboard to upload the required documents.
            
            Best regards,
            WCM Team
            """
        )
        
        return jsonify({'success': True, 'request_id': str(result.inserted_id)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def send_email(to_email, subject, body):
    try:
        msg = Message(
            subject=subject,
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[to_email],
            body=body
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

def get_time_ago(timestamp):
    """Helper function to convert timestamp to relative time"""
    if not timestamp:
        return ''
    
    now = datetime.now(timezone.utc)
    diff = now - timestamp
    
    if diff.days > 0:
        return f"{diff.days} days ago"
    elif diff.seconds >= 3600:
        hours = diff.seconds // 3600
        return f"{hours} hours ago"
    elif diff.seconds >= 60:
        minutes = diff.seconds // 60
        return f"{minutes} minutes ago"
    else:
        return "Just now"

# Admin routes
def fetch_google_sheet_data(sheet_url):
    """Fetch data from Google Sheets with error handling for different URL formats"""
    try:
        # Handle Google Doc URLs differently
        if 'document/d' in sheet_url:
            # For Google Docs, return empty data since we can't process it like a sheet
            print(f"Warning: URL {sheet_url} is a Google Doc, not a Sheet")
            return []
            
        # Extract sheet ID
        if '/d/' in sheet_url:
            sheet_id = sheet_url.split('/d/')[1].split('/')[0]
        else:
            print(f"Warning: Invalid Google Sheets URL format: {sheet_url}")
            return []
            
        # Extract gid (sheet name) if present
        sheet_name = ''
        if 'gid=' in sheet_url:
            sheet_name = sheet_url.split('gid=')[1].split('#')[0].split('&')[0]
        
        # Construct the CSV export URL
        sheet_url_csv = f'https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq?tqx=out:csv'
        if sheet_name:
            sheet_url_csv += f'&gid={sheet_name}'
            
        # Read the data
        df = pd.read_csv(sheet_url_csv)
        
        # Ensure 'created_at' is in datetime format if present
        if 'created_at' in df.columns:
            df['created_at'] = pd.to_datetime(df['created_at'], errors='coerce')
        
        return df.to_dict(orient='records')
        
    except Exception as e:
        print(f"Error fetching Google Sheet data: {str(e)}")
        return []

google_sheets_links = {
    'cda': 'https://docs.google.com/spreadsheets/d/1uQkXcXNZvn52WfSNedLfe5awIG2MqWH-vA6PrUFedbA/edit?gid=357150400#gid=357150400',
    'contract': 'https://docs.google.com/spreadsheets/d/1k9VcC9EKjo_euV-yKrX72dSEoUC6_Y5X9uGjWYH-ZIs/edit?gid=733412100#gid=733412100',
    'mlo': 'https://docs.google.com/spreadsheets/d/1qLfpE9RxMgyE9HNXOq98o9WFzzMkEQGmQ7LMIzj9NHs/edit',
    'pda': 'https://docs.google.com/spreadsheets/d/1hyLNAkOz6jewsRepZ3xWKesRcFK-xtfG4qktR9d2dss/edit?gid=1835127456#gid=1835127456'
}

def store_google_form_data(sheet_url, form_type):
    """Store Google Form data with error handling"""
    try:
        data = fetch_google_sheet_data(sheet_url)
        if not data:
            print(f"No data found for form type: {form_type}")
            return
            
        for entry in data:
            entry['form_type'] = form_type
            entry['status'] = 'pending'
            # Only insert if the entry doesn't already exist
            form_statuses.update_one(
                {
                    'form_type': form_type,
                    'created_at': entry.get('created_at')
                },
                {'$setOnInsert': entry},
                upsert=True
            )
    except Exception as e:
        print(f"Error storing Google Form data for {form_type}: {str(e)}")

def calculate_pending_tasks():
    result = [
        (list(tickets.find({'status': 'open'})), 'tickets'),
        (list(pda_submissions.find({'status': 'pending'})), 'pda'),
        (list(request_closing.find({'status': 'pending'})), 'closing_requests'),
        (list(db.cda_requests.find({'status': 'pending'})), 'cda_requests'),
        (list(db.dropbox_files.find({'status': 'pending'})), 'dropbox_files'),
        (list(onboarding_collection.find({'status': 'pending'})), 'onboarding'),
        (list(room_bookings.find({'status': 'pending'})), 'room_bookings'),
        (list(db.contract_requests.find({'status': 'pending'})), 'contract_requests'),
        (list(db.login_requests.find({'status': 'pending'})), 'login_requests')
    ]

    # Convert ObjectId to string for JSON serialization
    for task_list, task_type in result:
        for item in task_list:
            item['_id'] = str(item['_id'])

    return result

@app.route('/admin')
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    # Get individual task counts
    open_tickets = tickets.count_documents({'status': 'open'})
    pending_pdas = pda_submissions.count_documents({'status': 'pending'})
    pending_closings = request_closing.count_documents({'status': 'pending'})
    
    # Create a list of pending tasks for the template
    pending_tasks = [
        {'type': 'Tickets', 'count': open_tickets},
        {'type': 'PDA Submissions', 'count': pending_pdas},
        {'type': 'Closing Requests', 'count': pending_closings}
    ]
    
    # Total count for other purposes
    total_pending = open_tickets + pending_pdas + pending_closings
    
    documents_count = db.dropbox_files.count_documents({})
    messages_count = tickets.count_documents({})
    meetings_count = room_bookings.count_documents({})
    
    recent_activities = []
    
    # Get recent dropbox uploads - using the correct path
    try:
        if dbx:
            result = dbx.files_list_folder('/WCM Dashboard')  # Updated path
            recent_uploads = []
            for entry in result.entries[:5]:  # Get last 5 entries
                if isinstance(entry, dropbox.files.FileMetadata):  # Only show files, not folders
                    recent_uploads.append({
                        'title': 'Document Uploaded',
                        'description': f"{entry.name} was uploaded to Dropbox",
                        'time_ago': get_time_ago(entry.client_modified),
                        'icon': 'bi-file-earmark',
                        'icon_class': 'blue'
                    })
            recent_activities.extend(recent_uploads)
    except Exception as e:
        print(f"Error fetching Dropbox activities: {str(e)}")
    
    # Get recent meetings
    try:
        recent_meetings = list(room_bookings.find().sort('created_at', -1).limit(5))
        for meeting in recent_meetings:
            created_at = meeting.get('created_at')
            if isinstance(created_at, (datetime, str)):
                if isinstance(created_at, str):
                    try:
                        created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    except:
                        created_at = None
                else:
                    created_at = None
                
                recent_activities.append({
                    'title': 'Meeting Scheduled',
                    'description': f"Conference room booked for {meeting.get('purpose', 'Unknown purpose')}",
                    'time_ago': get_time_ago(created_at),
                    'icon': 'bi-calendar-event',
                    'icon_class': 'green'
                })
    except Exception as e:
        print(f"Error fetching meeting activities: {str(e)}")
    
    # Sort activities by time
    recent_activities.sort(key=lambda x: x['time_ago'], reverse=True)
    
    # Limit to most recent 10 activities
    recent_activities = recent_activities[:10]
    
    return render_template('admin/dashboard.html',
                         pending_tasks=pending_tasks,
                         total_pending=total_pending,
                         documents_count=documents_count,
                         messages_count=messages_count,
                         meetings_count=meetings_count,
                         recent_activities=recent_activities)

@app.route('/admin/pda/')
@app.route('/admin/pda/submissions')
def admin_pda():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    submissions = list(pda_submissions.find().sort([('status', 1), ('created_at', -1)]))
    for submission in submissions:
        submission['_id'] = str(submission['_id'])
        if 'created_at' not in submission:
            submission['created_at'] = datetime.now(timezone.utc)
        elif not isinstance(submission['created_at'], datetime):
            submission['created_at'] = datetime.now(timezone.utc)
        
        if 'status' not in submission:
            submission['status'] = 'pending'
            pda_submissions.update_one(
                {'_id': ObjectId(submission['_id'])},
                {'$set': {'status': 'pending'}}
            )
        
        if 'user_name' not in submission:
            submission['user_name'] = 'Unknown User'
        if 'email' not in submission:
            submission['email'] = 'No email provided'
        if 'user_id' not in submission:
            submission['user_id'] = 'Unknown ID'
        if 'answers' not in submission:
            submission['answers'] = {}
    
    return render_template('admin/pda.html', submissions=submissions if submissions else [], pending_tasks=pending_tasks, pending_tasks_count=pending_tasks_count)

@app.route('/admin/pda/<submission_id>')
def view_pda_submission(submission_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        submission = pda_submissions.find_one({'_id': ObjectId(submission_id)})
        if not submission:
            return jsonify({'error': 'Submission not found'}), 404
        
        submission['_id'] = str(submission['_id'])
        return jsonify(submission), 200
        
    except InvalidId:
        return jsonify({'error': 'Invalid submission ID'}), 400
    except Exception as e:
        print(f"Error retrieving PDA submission: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/pda/<submission_id>/status', methods=['POST'])
def update_pda_status(submission_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        status = data.get('status')
        
        if status not in ['approved', 'rejected']:
            return jsonify({'error': 'Invalid status'}), 400
        
        result = pda_submissions.update_one(
            {'_id': ObjectId(submission_id)},
            {
                '$set': {
                    'status': status,
                    'updated_at': datetime.now(timezone.utc),
                    'updated_by': session['user_id']
                }
            }
        )
        
        if result.modified_count:
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Submission not found'}), 404
        
    except InvalidId:
        return jsonify({'error': 'Invalid submission ID'}), 400
    except Exception as e:
        print(f"Error updating PDA status: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/pda/<submission_id>/accept', methods=['POST'])
def accept_pda_submission(submission_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        result = pda_submissions.update_one(
            {'_id': ObjectId(submission_id)},
            {'$set': {
                'status': 'accepted',
                'updated_at': datetime.now(timezone.utc),
                'updated_by': session['user_id']
            }}
        )
        
        if result.modified_count:
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Submission not found'}), 404
        
    except InvalidId:
        return jsonify({'error': 'Invalid submission ID'}), 400
    except Exception as e:
        print(f"Error accepting PDA submission: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/pda/<submission_id>/decline', methods=['POST'])
def decline_pda_submission(submission_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        result = pda_submissions.update_one(
            {'_id': ObjectId(submission_id)},
            {'$set': {
                'status': 'declined',
                'updated_at': datetime.now(timezone.utc),
                'updated_by': session['user_id']
            }}
        )
        
        if result.modified_count:
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Submission not found'}), 404
        
    except InvalidId:
        return jsonify({'error': 'Invalid submission ID'}), 400
    except Exception as e:
        print(f"Error declining PDA submission: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/tickets/new')
@app.route('/admin/tickets')
def admin_tickets():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    all_tickets = list(tickets.find().sort('created_at', -1))
    for ticket in all_tickets:
        if 'created_at' not in ticket:
            ticket['created_at'] = datetime.now(timezone.utc)
        elif not isinstance(ticket['created_at'], datetime):
            ticket['created_at'] = datetime.now(timezone.utc)
    
    return render_template('admin/tickets.html', tickets=all_tickets if all_tickets else [], pending_tasks=pending_tasks, pending_tasks_count=pending_tasks_count)

@app.route('/admin/tickets/close/<ticket_id>', methods=['POST'])
def close_ticket(ticket_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        result = tickets.update_one(
            {'_id': ObjectId(ticket_id)},
            {'$set': {
                'status': 'closed',
                'closed_at': datetime.now(timezone.utc),
                'closed_by': session['user_id']
            }}
        )
        
        if result.modified_count:
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Ticket not found'}), 404
        
    except Exception as e:
        print(f"Error closing ticket: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Trish build your logic over here.. these are just sample routes to get you started, you can modify them as needed fir fubctionality part
#all of the following are incomplete routes, you need to build the logic to display the data as needed
#check the rendered html file once to see which all fields are needed to be displayed

@app.route('/admin/tasks')
def admin_tasks():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    
    return render_template('admin/tasks.html', pending_tasks=pending_tasks, pending_tasks_count=pending_tasks_count)

@app.route('/admin/display/dropbox')
def admin_dropbox():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    dropbox_files = list(db.dropbox_files.find().sort('created_at', -1))
    return render_template('admin/dropbox.html', dropbox_files=dropbox_files, pending_tasks=pending_tasks, pending_tasks_count=pending_tasks_count)

@app.route('/admin/google-form/response')
def admin_google_form_response():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    # Store Google Form data into the database
    store_google_form_data(google_sheets_links['cda'], 'cda')
    store_google_form_data(google_sheets_links['contract'], 'contract')
    store_google_form_data(google_sheets_links['mlo'], 'mlo')
    store_google_form_data(google_sheets_links['pda'], 'pda')
    
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    
    return render_template('admin/google_form_response.html', 
                           pending_tasks_count=pending_tasks_count,
                           pending_tasks=pending_tasks)

@app.route('/admin/form-status/<form_id>/update', methods=['POST'])
def update_form_status(form_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        status = data.get('status')
        
        if status not in ['approved', 'pending']:
            return jsonify({'error': 'Invalid status'}), 400
        
        result = form_statuses.update_one(
            {'_id': ObjectId(form_id)},
            {
                '$set': {
                    'status': status,
                    'updated_at': datetime.now(timezone.utc),
                    'updated_by': session['user_id']
                }
            }
        )
        
        if result.modified_count:
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Form not found'}), 404
        
    except InvalidId:
        return jsonify({'error': 'Invalid form ID'}), 400
    except Exception as e:
        print(f"Error updating form status: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/contract-requests')
def admin_contract_requests():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    contract_requests = list(db.contract_requests.find().sort('created_at', -1))
    for request in contract_requests:
        request['_id'] = str(request['_id'])
        request['created_at'] = request['created_at'].astimezone(timezone.utc)
        request['last_day'] = request['last_day'].astimezone(timezone.utc)
    
    return render_template('admin/contract_requests.html', contract_requests=contract_requests if contract_requests else [], pending_tasks=pending_tasks, pending_tasks_count=pending_tasks_count)

@app.route('/admin/contract-requests/<request_id>/status', methods=['POST'])
def update_contract_request_status(request_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        status = data.get('status')
        
        if status not in ['accepted', 'declined']:
            return jsonify({'error': 'Invalid status'}), 400
        
        result = db.contract_requests.update_one(
            {'_id': ObjectId(request_id)},
            {
                '$set': {
                    'status': status,
                    'updated_at': datetime.now(timezone.utc),
                    'updated_by': session['user_id']
                }
            }
        )
        
        if result.modified_count:
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Request not found'}), 404
        
    except InvalidId:
        return jsonify({'error': 'Invalid request ID'}), 400
    except Exception as e:
        print(f"Error updating contract request status: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/contract-requests/<request_id>/accept', methods=['POST'])
def accept_contract_request(request_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        result = db.contract_requests.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {
                'status': 'accepted',
                'updated_at': datetime.now(timezone.utc),
                'updated_by': session['user_id']
            }}
        )
        
        if result.modified_count:
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Request not found'}), 404
        
    except InvalidId:
        return jsonify({'error': 'Invalid request ID'}), 400
    except Exception as e:
        print(f"Error accepting contract request: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/contract-requests/<request_id>/decline', methods=['POST'])
def decline_contract_request(request_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        result = db.contract_requests.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {
                'status': 'declined',
                'updated_at': datetime.now(timezone.utc),
                'updated_by': session['user_id']
            }}
        )
        
        if result.modified_count:
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Request not found'}), 404
        
    except InvalidId:
        return jsonify({'error': 'Invalid request ID'}), 400
    except Exception as e:
        print(f"Error declining contract request: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/onboarding-requests')
def admin_onboarding_requests():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    onboarding_requests = list(onboarding_collection.find({'status': 'pending'}).sort('created_at', -1))
    return render_template('admin/login_requests.html', onboarding_requests=onboarding_requests if onboarding_requests else [], pending_tasks=pending_tasks, pending_tasks_count=pending_tasks_count)

@app.route('/admin/onboarding')
def admin_onboarding():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    onboarding_records = list(onboarding_collection.find().sort('created_at', -1))
    for record in onboarding_records:
        if 'start_date' not in record:
            record['start_date'] = None  # or set a default date if preferred
    return render_template('admin/onboarding.html', records=onboarding_records if onboarding_records else [], pending_tasks=pending_tasks, pending_tasks_count=pending_tasks_count)

@app.route('/admin/closing-requests')
def admin_closing_requests():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    # Fetch closing requests data from MongoDB
    closing_requests_list = list(request_closing.find().sort('created_at', -1))
    
    # Convert ObjectId to string for JSON serialization and format data
    for request in closing_requests_list:
        request['_id'] = str(request['_id'])
        request['created_at'] = request['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        if 'last_day' in request and request['last_day'] and isinstance(request['last_day'], datetime):
            request['last_day'] = request['last_day'].strftime('%Y-%m-%d')
    
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    return render_template('admin/closing_requests.html', requests=closing_requests_list, pending_tasks=pending_tasks, pending_tasks_count=pending_tasks_count)

@app.route('/admin/closing-requests/<request_id>/status', methods=['POST'])
def update_closing_request_status(request_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        status = data.get('status')
        
        if status not in ['approved', 'rejected']:
            return jsonify({'error': 'Invalid status'}), 400
        
        result = request_closing.update_one(
            {'_id': ObjectId(request_id)},
            {
                '$set': {
                    'status': status,
                    'updated_at': datetime.now(timezone.utc),
                    'updated_by': session['user_id']
                }
            }
        )
        
        if result.modified_count:
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Request not found'}), 404
        
    except InvalidId:
        return jsonify({'error': 'Invalid request ID'}), 400
    except Exception as e:
        print(f"Error updating closing request status: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/closing-requests/<request_id>/accept', methods=['POST'])
def accept_closing_request(request_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        result = request_closing.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {
                'status': 'accepted',
                'updated_at': datetime.now(timezone.utc),
                'updated_by': session['user_id']
            }}
        )
        
        if result.modified_count:
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Request not found'}), 404
        
    except InvalidId:
        return jsonify({'error': 'Invalid request ID'}), 400
    except Exception as e:
        print(f"Error accepting closing request: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/closing-requests/<request_id>/decline', methods=['POST'])
def decline_closing_request(request_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        result = request_closing.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {
                'status': 'declined',
                'updated_at': datetime.now(timezone.utc),
                'updated_by': session['user_id']
            }}
        )
        
        if result.modified_count:
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Request not found'}), 404
        
    except InvalidId:
        return jsonify({'error': 'Invalid request ID'}), 400
    except Exception as e:
        print(f"Error declining closing request: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/google-form/cda')
def admin_google_form_cda():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    cda_requests = fetch_google_sheet_data(google_sheets_links['cda'])
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    # cda_requests = list(db.google_form_responses.find({'form_type': 'cda'}).sort('created_at', -1))
    
    return render_template('admin/google_form_cda.html', 
                           analysis=cda_requests, 
                           pending_tasks_count=pending_tasks_count,
                           pending_tasks=pending_tasks)

@app.route('/admin/google-form/contract')
def admin_google_form_contract():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    contract_requests = fetch_google_sheet_data(google_sheets_links['contract'])
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    
    return render_template('admin/google_form_contract.html', 
                           analysis=contract_requests, 
                           pending_tasks_count=pending_tasks_count,
                           pending_tasks=pending_tasks)

@app.route('/admin/google-form/mlo')
def admin_google_form_login():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    mlo_requests = fetch_google_sheet_data(google_sheets_links['mlo'])
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    
    return render_template('admin/google_form_login.html', 
                           analysis=mlo_requests, 
                           pending_tasks_count=pending_tasks_count,
                           pending_tasks=pending_tasks)

@app.route('/admin/google-form/pda')
def admin_google_form_pda():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    pda_requests = fetch_google_sheet_data(google_sheets_links['pda'])
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    
    return render_template('admin/google_form_pda.html', 
                           analysis=pda_requests, 
                           pending_tasks_count=pending_tasks_count,
                           pending_tasks=pending_tasks)

@app.route('/admin/onboarding-requests/<request_id>/status', methods=['POST'])
def update_onboarding_request_status(request_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        status = data.get('status')
        
        if status not in ['completed', 'pending']:
            return jsonify({'error': 'Invalid status'}), 400
        
        result = onboarding_collection.update_one(
            {'_id': ObjectId(request_id)},
            {
                '$set': {
                    'status': status,
                    'updated_at': datetime.now(timezone.utc),
                    'updated_by': session['user_id']
                }
            }
        )
        
        if result.modified_count:
            return jsonify({'success': True}), 200
        return jsonify({'error': 'Request not found'}), 404
        
    except InvalidId:
        return jsonify({'error': 'Invalid request ID'}), 400
    except Exception as e:
        print(f"Error updating onboarding request status: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/accepted-onboarding-requests')
def accepted_onboarding_requests():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    accepted_requests = list(onboarding_collection.find({'status': 'completed'}).sort('created_at', -1))
    return render_template('admin/accepted_login_requests.html', accepted_requests=accepted_requests, pending_tasks=pending_tasks, pending_tasks_count=pending_tasks_count)

@app.route('/admin/rejected-onboarding-requests')
def rejected_onboarding_requests():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    rejected_requests = list(onboarding_collection.find({'status': 'rejected'}).sort('created_at', -1))
    return render_template('admin/rejected_login_requests.html', rejected_requests=rejected_requests, pending_tasks=pending_tasks, pending_tasks_count=pending_tasks_count)

@app.route('/admin/pending-tasks')
def get_pending_tasks():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        pending_tasks = calculate_pending_tasks()
        pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
        
        tasks_by_category = {}
        for tasks, category in pending_tasks:
            tasks_by_category[category] = [
                {
                    '_id': str(task['_id']),
                    'status': task.get('status', 'pending'),
                    'created_at': task['created_at'].isoformat() if isinstance(task.get('created_at'), datetime) else None,
                    'updated_at': task['updated_at'].isoformat() if isinstance(task.get('updated_at'), datetime) else None
                }
                for task in tasks
            ]
        
        return jsonify({
            'success': True,
            'pending_tasks': tasks_by_category,
            'total_count': pending_tasks_count
        })
        
    except Exception as e:
        print(f"Error getting pending tasks: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/pending-tasks/count')
def pending_tasks():
    # ...existing code...
    count = len(calculate_pending_tasks()) # Assuming this function returns the count of pending_tasks
    print(count)  # Print the count for debuggingget_pending_tasks_count() 
    return jsonify({'count': count})

@app.route('/admin/bookings')
def admin_bookings():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login.loginf'))
    
    # Collect room bookings data
    room_bookings_list = list(room_bookings.find().sort('created_at', -1))
    
    # Convert ObjectId to string for JSON serialization and format data
    for booking in room_bookings_list:
        booking['_id'] = str(booking['_id'])
        booking['date'] = booking['date'].strftime('%B %d, %Y')
        booking['start_time'] = booking['start_time'].strftime('%I:%M %p')
        booking['end_time'] = booking['end_time'].strftime('%I:%M %p')
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    pending_tasks = calculate_pending_tasks()
    
    return render_template('admin/bookings.html', room_bookings=room_bookings_list, pending_tasks=pending_tasks, pending_tasks_count=pending_tasks_count)

@app.route('/admin/room-bookings')
def admin_room_bookings():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    # Fetch all room bookings
    bookings = list(room_bookings.find())
    
    # Process each booking
    for booking in bookings:
        # Convert ObjectId to string
        booking['_id'] = str(booking['_id'])
        if 'user_id' in booking:
            booking['user_id'] = str(booking['user_id'])
        
        # Format dates
        if 'created_at' in booking:
            booking['created_at'] = booking['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        # Ensure status exists
        if 'status' not in booking:
            booking['status'] = 'pending'
    
    # Sort bookings by date and time
    bookings.sort(key=lambda x: (x.get('date', ''), x.get('start_time', '')), reverse=True)
    
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    
    return render_template(
        'admin/room_bookings.html',
        bookings=bookings,
        pending_tasks=pending_tasks,
        pending_tasks_count=pending_tasks_count
    )

@app.route('/admin/room-bookings/<booking_id>/status', methods=['POST'])
def update_room_booking_status(booking_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        status = data.get('status')
        if not status:
            return jsonify({'error': 'Status is required'}), 400
        
        if status not in ['approved', 'rejected']:
            return jsonify({'error': 'Invalid status. Must be approved or rejected'}), 400
        
        # Validate booking ID format
        try:
            booking_id_obj = ObjectId(booking_id)
        except InvalidId:
            return jsonify({'error': 'Invalid booking ID format'}), 400
        
        # Check if booking exists
        booking = room_bookings.find_one({'_id': booking_id_obj})
        if not booking:
            return jsonify({'error': 'Room booking not found'}), 404
            
        # Check if booking is already processed
        if booking.get('status') in ['approved', 'rejected']:
            return jsonify({'error': 'Booking has already been processed'}), 400
        
        # Update the booking
        result = room_bookings.update_one(
            {'_id': booking_id_obj},
            {
                '$set': {
                    'status': status,
                    'updated_at': datetime.now(timezone.utc),
                    'updated_by': str(session['user_id'])
                }
            }
        )

        if result.modified_count:
            # Get updated booking for response
            updated_booking = room_bookings.find_one({'_id': booking_id_obj})
            if updated_booking:
                # Convert ObjectId to string
                updated_booking['_id'] = str(updated_booking['_id'])
                if 'user_id' in updated_booking:
                    updated_booking['user_id'] = str(updated_booking['user_id'])
                if 'updated_at' in updated_booking:
                    updated_booking['updated_at'] = updated_booking['updated_at'].strftime('%Y-%m-%d %H:%M:%S')
                
                return jsonify({
                    'success': True,
                    'message': f'Room booking {status} successfully',
                    'booking': updated_booking
                }), 200
            
            return jsonify({
                'success': True,
                'message': f'Room booking {status} successfully'
            }), 200
            
        return jsonify({'error': 'Failed to update room booking'}), 500
        
    except Exception as e:
        print(f"Error updating room booking status: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

def list_dropbox_files(path):
    """Fetches the list of files from a specific Dropbox folder"""
    global dbx
    try:
        if dbx is None:
            init_dropbox_client()
        
        if not dbx:
            return {"error": "Failed to initialize Dropbox client"}
                
        # Ensure path starts with /Apps/WCM Dashboard
        if not path.startswith('/WCM Dashboard'):
            path = f"/WCM Dashboard{path}"
            
        response = dbx.files_list_folder(path)
        files = [{"name": entry.name, "path": entry.path_display} for entry in response.entries]
        return files
    except Exception as e:
        print(f"Dropbox error: {str(e)}")
        return {"error": str(e)}

def list_dropbox_folders(path):
    """Fetches the list of folders from a specific Dropbox folder"""
    global dbx
    try:
        if dbx is None:
            init_dropbox_client()
        
        if not dbx:
            return {"error": "Failed to initialize Dropbox client"}
                
        # Ensure path starts with /Apps/WCM Dashboard
        if not path.startswith('/WCM Dashboard'):
            path = f"/WCM Dashboard{path}"
            
        response = dbx.files_list_folder(path)
        folders = [{"name": entry.name, "path": entry.path_display} 
                  for entry in response.entries 
                  if isinstance(entry, dropbox.files.FolderMetadata)]
        return folders
    except Exception as e:
        print(f"Dropbox error: {str(e)}")
        return {"error": str(e)}

@app.route('/onboarding-status')
def get_onboarding_status():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    try:
        # Get user's onboarding status from database
        status = onboarding_collection.find_one({'user_id': session['user_id']})
        
        if not status:
            # Initialize status if it doesn't exist
            default_status = {
                'user_id': session['user_id'],
                'w9_completed': False,
                'id_completed': False,
                'contract_completed': False,
                'sign_completed': False,
                'license_completed': False,
                'login_completed': False,
                'created_at': datetime.now(timezone.utc)
            }
            onboarding_collection.insert_one(default_status)
            return jsonify(default_status)
            
        # Remove MongoDB _id before sending response
        status.pop('_id', None)
        return jsonify(status)
        
    except Exception as e:
        print(f"Error fetching onboarding status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/mark-complete/<step>', methods=['POST'])
def mark_step_complete(step):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    valid_steps = ['w9', 'id', 'contract', 'sign', 'license', 'login']
    if step not in valid_steps:
        return jsonify({'error': 'Invalid step'}), 400
        
    try:
        # Update the step status in database
        update_field = f'{step}_completed'
        result = onboarding_collection.update_one(
            {'user_id': session['user_id']},
            {
                '$set': {
                    update_field: True,
                    'updated_at': datetime.now(timezone.utc)
                }
            },
            upsert=True
        )
        
        return jsonify({
            'success': True,
            'message': f'{step} marked as complete'
        })
        
    except Exception as e:
        print(f"Error marking step complete: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/submit-onboarding', methods=['POST'])
def submit_onboarding():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    try:
        # Get the submitted data
        data = request.get_json()
        
        # Get user details
        user = employees.find_one({'_id': ObjectId(session['user_id'])})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Create submission document
        submission = {
            'user_id': session['user_id'],
            'user_name': f"{user.get('first_name', '')} {user.get('last_name', '')}",
            'email': user.get('email', ''),
            'steps': data.get('steps', {}),
            'status': 'completed',
            'submitted_at': datetime.now(timezone.utc),
            'created_at': datetime.now(timezone.utc)
        }
        
        # Insert into onboarding collection
        result = onboarding_collection.insert_one(submission)
        
        if result.inserted_id:
            # Update user's onboarding status
            employees.update_one(
                {'_id': ObjectId(session['user_id'])},
                {
                    '$set': {
                        'onboarding_completed': True,
                        'onboarding_completed_at': datetime.now(timezone.utc)
                    }
                }
            )
            
            return jsonify({
                'success': True,
                'message': 'Onboarding completed successfully',
                'submission_id': str(result.inserted_id)
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to save onboarding submission'
            }), 500
            
    except Exception as e:
        print(f"Error submitting onboarding: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/cda')
@login_required
def cda():
    return render_template('cda.html')

@app.route('/api/cda/submit', methods=['POST'])
@login_required
def submit_cda():
    try:
        # Get the current user
        user_id = session.get('user_id')
        user = employees.find_one({'_id': ObjectId(user_id)})
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
            
        # Create CDA submission record
        cda_data = {
            'user_id': ObjectId(user_id),
            'user_email': user.get('email'),
            'user_name': user.get('name'),
            'form_completed': True,
            'status': 'submitted',
            'created_at': datetime.now(timezone.utc)
        }
        
        # Insert into cda collection
        result = db.cda.insert_one(cda_data)
        
        if result.inserted_id:
            return jsonify({
                'success': True,
                'message': 'CDA form submission recorded successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to record CDA submission'
            }), 500
            
    except Exception as e:
        print(f"Error in submit_cda: {str(e)}")  # Add logging
        return jsonify({
            'success': False,
            'message': f'An error occurred: {str(e)}'
        }), 500

@app.route('/api/submit_closing_request', methods=['POST'])
@login_required
def submit_closing_request_api():
    try:
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Content-Type must be application/json'
            }), 400

        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400

        # Get user information
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({
                'success': False,
                'error': 'User not authenticated'
            }), 401

        employee = employees.find_one({'_id': ObjectId(user_id)})
        if not employee:
            return jsonify({
                'success': False,
                'error': 'Employee not found'
            }), 404

        # Extract form data and document statuses
        form_data = data.get('formData', {})
        document_statuses = data.get('documentStatuses', {})

        # Validate required fields
        required_fields = [
            'borrowerName', 'propertyAddress', 'phoneNumber', 'emailAddress',
            'loName', 'loPhone', 'loEmail',
            'processorName', 'processorPhone', 'processorEmail',
            'escrowCompany', 'escrowContact', 'escrowEmail'
        ]

        missing_fields = [field for field in required_fields if not form_data.get(field)]
        if missing_fields:
            return jsonify({
                'success': False,
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400

        # Create closing request record
        closing_request = {
            'user_id': ObjectId(user_id),
            'employee_name': employee.get('name'),
            'form_data': form_data,
            'document_statuses': document_statuses,
            'status': 'pending',
            'created_at': datetime.now(timezone.utc),
            'updated_at': datetime.now(timezone.utc)
        }

        # Insert into MongoDB
        result = request_closing.insert_one(closing_request)
        
        if not result.inserted_id:
            return jsonify({
                'success': False,
                'error': 'Failed to save closing request'
            }), 500

        print(f"Closing request submitted successfully. ID: {result.inserted_id}")
        return jsonify({
            'success': True,
            'message': 'Closing request submitted successfully',
            'request_id': str(result.inserted_id)
        })

    except Exception as e:
        print(f"Error in submit_closing_request: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'An unexpected error occurred: {str(e)}'
        }), 500

@app.route('/admin/login-requests')
def admin_login_requests():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    # Fetch all login requests
    requests = list(login_requests.find())
    
    # Process each request
    for request in requests:
        # Convert ObjectId to string
        request['_id'] = str(request['_id'])
        if 'user_id' in request:
            request['user_id'] = str(request['user_id'])
        
        # Format dates
        if 'created_at' in request:
            request['created_at'] = request['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        # Ensure status exists
        if 'status' not in request:
            request['status'] = 'pending'
    
    # Sort requests by creation date
    requests.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    pending_tasks = calculate_pending_tasks()
    pending_tasks_count = sum(len(tasks) for tasks, _ in pending_tasks)
    
    return render_template(
        'admin/login_requests.html',
        requests=requests,
        pending_tasks=pending_tasks,
        pending_tasks_count=pending_tasks_count
    )

@app.route('/admin/login-requests/<request_id>/status', methods=['POST'])
def update_login_request_status(request_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        status = data.get('status')
        if not status:
            return jsonify({'error': 'Status is required'}), 400
        
        if status not in ['approved', 'rejected']:
            return jsonify({'error': 'Invalid status. Must be approved or rejected'}), 400
        
        # Validate request ID format
        try:
            request_id_obj = ObjectId(request_id)
        except InvalidId:
            return jsonify({'error': 'Invalid request ID format'}), 400
        
        # Check if request exists
        login_request = login_requests.find_one({'_id': request_id_obj})
        if not login_request:
            return jsonify({'error': 'Login request not found'}), 404
            
        # Check if request is already processed
        if login_request.get('status') in ['approved', 'rejected']:
            return jsonify({'error': 'Request has already been processed'}), 400
        
        # Update the request
        result = login_requests.update_one(
            {'_id': request_id_obj},
            {
                '$set': {
                    'status': status,
                    'updated_at': datetime.now(timezone.utc),
                    'updated_by': str(session['user_id'])
                }
            }
        )

        if result.modified_count:
            # If approved, create user account
            if status == 'approved':
                try:
                    # Hash the default password
                    default_password = generate_password_hash('Welcome@123')
                    
                    # Create user document
                    user_data = {
                        'email': login_request['email'],
                        'password': default_password,
                        'name': login_request['employee_name'],
                        'department': login_request.get('department', ''),
                        'role': login_request.get('role', 'user'),
                        'created_at': datetime.now(timezone.utc),
                        'is_active': True,
                        'is_admin': False
                    }
                    
                    users.insert_one(user_data)
                    
                    # Send email with login credentials
                    send_welcome_email(login_request['email'], login_request['employee_name'])
                except Exception as e:
                    print(f"Error creating user account: {str(e)}")
                    # Don't return error - the status update was successful
            
            # Get updated request for response
            updated_request = login_requests.find_one({'_id': request_id_obj})
            if updated_request:
                # Convert ObjectId to string
                updated_request['_id'] = str(updated_request['_id'])
                if 'user_id' in updated_request:
                    updated_request['user_id'] = str(updated_request['user_id'])
                if 'updated_at' in updated_request:
                    updated_request['updated_at'] = updated_request['updated_at'].strftime('%Y-%m-%d %H:%M:%S')
                
                return jsonify({
                    'success': True,
                    'message': f'Login request {status} successfully',
                    'request': updated_request
                }), 200
            
            return jsonify({
                'success': True,
                'message': f'Login request {status} successfully'
            }), 200
            
        return jsonify({'error': 'Failed to update login request'}), 500
        
    except Exception as e:
        print(f"Error updating login request status: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

def send_welcome_email(email, name):
    """Send welcome email with login credentials"""
    subject = "Welcome to WCM Dashboard - Your Account Details"
    body = f"""
    Dear {name},
    
    Your account for the WCM Dashboard has been created. You can now log in using the following credentials:
    
    Email: {email}
    Password: Welcome@123
    
    Please change your password after your first login for security purposes.
    
    Best regards,
    WCM Dashboard Team
    """
    
    try:
        msg = Message(subject, recipients=[email], body=body)
        mail.send(msg)
    except Exception as e:
        print(f"Error sending welcome email: {str(e)}")

if __name__ == '__main__':
    print("Starting WCM Dashboard application...")
    insert_sample_employees()  # Create sample employees on startup
    print("Starting Flask development server...")
    app.run(debug=True, use_reloader=False, port=5000)  # Disable reloader to prevent duplicate threads
