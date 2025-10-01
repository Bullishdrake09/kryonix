import os
import json
import time
import secrets
from datetime import datetime, timedelta # Import timedelta for timeouts
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
app.config['SECRET_KEY'] = 'YOUR_VERY_SECRET_KEY' # !!! CHANGE THIS TO A STRONG, UNIQUE KEY !!!
app.config['USER_DATA_FILE'] = 'users.json'
app.config['BANNED_EMAILS_FILE'] = 'banned_emails.json' # New file for banned emails
app.config['UPLOAD_FOLDER'] = 'uploads' # Folder to store uploaded files (for chat media)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size

# Create upload folder if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to 'login' route if not authenticated


def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# --- User Management (Flask-Login) ---
class User(UserMixin):
    def __init__(self, id, username, email, password_hash, friends=None, requests=None, blocked=None, chat_history=None, settings=None, timeout_until=None):
        self.id = id # This is the username in our case
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.friends = friends if friends is not None else []
        self.requests = requests if requests is not None else [] # Incoming requests
        self.blocked = blocked if blocked is not None else [] # Users blocked by this user
        self.chat_history = chat_history if chat_history is not None else {} # {room_name: [{msg_obj}]}
        self.settings = settings if settings is not None else {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'}
        # For timeout functionality: store as string (ISO format) for JSON serialization
        self.timeout_until = datetime.fromisoformat(timeout_until) if timeout_until else None

    @property
    def is_timed_out(self):
        return self.timeout_until and self.timeout_until > datetime.now()

    @staticmethod
    def get(user_id):
        user_data = load_user_data(user_id)
        if user_data:
            return User(user_data['username'], user_data['username'], user_data['email'],
                        user_data['password'], user_data.get('friends'),
                        user_data.get('requests'), user_data.get('blocked'),
                        user_data.get('chat_history'), user_data.get('settings'),
                        user_data.get('timeout_until'))
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# --- Data Persistence Functions ---
def load_all_users_data():
    """Loads all user data from the JSON file."""
    if not os.path.exists(app.config['USER_DATA_FILE']):
        return {}
    with open(app.config['USER_DATA_FILE'], 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            app.logger.warning(f"Could not decode JSON from {app.config['USER_DATA_FILE']}. Initializing with empty data.")
            return {}

def save_all_users_data(all_users_data):
    """Saves all user data to the JSON file."""
    with open(app.config['USER_DATA_FILE'], 'w') as f:
        json.dump(all_users_data, f, indent=4)

def load_user_data(username):
    """Loads a single user's data."""
    all_users = load_all_users_data()
    return all_users.get(username)

def save_user_data(user_data_dict):
    """Saves a single user's data (updates the overall dict)."""
    all_users = load_all_users_data()
    all_users[user_data_dict['username']] = user_data_dict
    save_all_users_data(all_users)

def get_user_by_username_or_email(login_field):
    """Finds a user by username or email."""
    all_users = load_all_users_data()
    for username, data in all_users.items():
        if username == login_field or data['email'] == login_field:
            return User(data['username'], data['username'], data['email'],
                        data['password'], data.get('friends'),
                        data.get('requests'), data.get('blocked'),
                        data.get('chat_history'), data.get('settings'),
                        data.get('timeout_until'))
    return None

def add_message_to_history(room, message_data):
    all_users = load_all_users_data()
    user1, user2 = room.split('-') # Room format: user1-user2
    
    # Update history for user1
    if user1 in all_users:
        if 'chat_history' not in all_users[user1]:
            all_users[user1]['chat_history'] = {}
        if room not in all_users[user1]['chat_history']:
            all_users[user1]['chat_history'][room] = []
        all_users[user1]['chat_history'][room].append(message_data)

    # Update history for user2
    if user2 in all_users:
        if 'chat_history' not in all_users[user2]:
            all_users[user2]['chat_history'] = {}
        if room not in all_users[user2]['chat_history']:
            all_users[user2]['chat_history'][room] = []
        all_users[user2]['chat_history'][room].append(message_data)
    
    save_all_users_data(all_users)

def update_message_in_history(room, message_id, new_text):
    all_users = load_all_users_data()
    user1, user2 = room.split('-')

    for user_key in [user1, user2]:
        if user_key in all_users and 'chat_history' in all_users[user_key] and room in all_users[user_key]['chat_history']:
            for msg in all_users[user_key]['chat_history'][room]:
                if msg.get('id') == message_id:
                    msg['msg'] = new_text
                    break
    save_all_users_data(all_users)


def delete_message_from_history(room, message_id):
    all_users = load_all_users_data()
    user1, user2 = room.split('-')

    for user_key in [user1, user2]:
        if user_key in all_users and 'chat_history' in all_users[user_key] and room in all_users[user_key]['chat_history']:
            for msg in all_users[user_key]['chat_history'][room]:
                if msg.get('id') == message_id:
                    msg['msg'] = "<em>deleted message</em>" # Mark as deleted
                    break
    save_all_users_data(all_users)

def get_room_history(room_name):
    user_data = load_user_data(current_user.username)
    if user_data and 'chat_history' in user_data and room_name in user_data['chat_history']:
        return user_data['chat_history'][room_name]
    return []

# --- Banned Emails Management ---
def load_banned_emails():
    if not os.path.exists(app.config['BANNED_EMAILS_FILE']):
        return []
    with open(app.config['BANNED_EMAILS_FILE'], 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            app.logger.warning(f"Could not decode JSON from {app.config['BANNED_EMAILS_FILE']}. Initializing with empty data.")
            return []

def save_banned_emails(banned_list):
    with open(app.config['BANNED_EMAILS_FILE'], 'w') as f:
        json.dump(banned_list, f, indent=4)

def is_email_banned(email):
    banned_list = load_banned_emails()
    return email in banned_list

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        all_users = load_all_users_data()
        banned_emails = load_banned_emails()

        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html', error='All fields are required.')

        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
            return render_template('register.html', error='Username must be at least 3 characters long.')

        if not "@" in email or "." not in email:
            flash('Invalid email format.', 'error')
            return render_template('register.html', error='Invalid email format.')
            
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html', error='Password must be at least 6 characters long.')

        if username in all_users:
            flash('Username already exists.', 'error')
            return render_template('register.html', error='Username already exists.')
        
        for user_data in all_users.values():
            if user_data['email'] == email:
                flash('Email already registered.', 'error')
                return render_template('register.html', error='Email already registered.')

        if email in banned_emails:
            flash('This email address is banned from registration.', 'error')
            return render_template('register.html', error='This email address is banned from registration.')

        hashed_password = generate_password_hash(password)
        new_user_data = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'friends': [],
            'requests': [],
            'blocked': [],
            'chat_history': {},
            'settings': {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'}, # Default theme
            'timeout_until': None # New field for timeouts
        }
        all_users[username] = new_user_data
        save_all_users_data(all_users)

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))

    if request.method == 'POST':
        login_field = request.form.get('login_field')
        password = request.form.get('password')

        user = get_user_by_username_or_email(login_field)

        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid username/email or password.', 'error')
            return render_template('login.html', error='Invalid username/email or password.')
        
        # Check if user is banned by email
        if is_email_banned(user.email):
            flash('Your account is banned.', 'error')
            logout_user() # Ensure they are logged out if somehow they got here
            return render_template('login.html', error='Your account is banned.')

        # Check if user is currently timed out
        if user.is_timed_out:
            flash(f'Your account is temporarily timed out until {user.timeout_until.strftime("%Y-%m-%d %H:%M")}.', 'warning')
            return render_template('login.html', error='Account timed out.')

        login_user(user)
        flash('Logged in successfully!', 'success')
        return redirect(url_for('chat'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    # If user is timed out, log them out and redirect to login
    if current_user.is_timed_out:
        flash(f'Your account is temporarily timed out until {current_user.timeout_until.strftime("%Y-%m-%d %H:%M")}.', 'warning')
        logout_user()
        return redirect(url_for('login'))

    user_data = load_user_data(current_user.username)
    friends_list = user_data.get('friends', [])
    
    session['primary_color'] = user_data['settings'].get('primary_color', '#0f0f0f')
    session['accent_color'] = user_data['settings'].get('accent_color', '#ff3f81')

    return render_template('chat.html', 
                           username=current_user.username, 
                           friends_list=friends_list,
                           current_user=current_user)

@app.route('/history/<room_name>')
@login_required
def history(room_name):
    user1, user2 = room_name.split('-')
    
    if not (current_user.username == user1 or current_user.username == user2):
        return jsonify({'error': 'Unauthorized to view this chat history'}), 403

    current_user_data = load_user_data(current_user.username)
    target_username = user2 if current_user.username == user1 else user1

    # Check friend status or if current user is blocked by target
    if target_username not in current_user_data.get('friends', []):
        target_user_data = load_user_data(target_username)
        if target_user_data and current_user.username in target_user_data.get('blocked', []):
             return jsonify({'error': f'You are blocked by {target_username}. Cannot view chat history.'}), 403
        return jsonify({'error': 'You are not friends with this user. Cannot view chat history.'}), 403

    history_messages = get_room_history(room_name)
    return jsonify(messages=history_messages)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:
        filename = secure_filename(file.filename)
        timestamp = int(time.time())
        unique_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        try:
            file.save(file_path)
            file_url = url_for('uploaded_file', filename=unique_filename)
            return jsonify({'url': file_url})
        except Exception as e:
            app.logger.error(f"Error saving file: {e}")
            return jsonify({'error': f'Failed to save file: {str(e)}'}), 500
    return jsonify({'error': 'File upload failed unexpectedly'}), 500

@app.route('/friends', methods=['GET', 'POST'])
@login_required
def friends():
    username = current_user.username
    user_data = load_user_data(username)
    message = None
    message_type = None

    if request.method == 'POST':
        action = request.form.get('action')
        target_username = request.form.get('target_username')

        if not target_username:
            message = "Target username is required."
            message_type = "error"
        elif target_username == username:
            message = "You cannot perform this action on yourself."
            message_type = "error"
        else:
            target_user_data = load_user_data(target_username)
            if not target_user_data:
                message = f"User '{target_username}' not found."
                message_type = "error"
            else:
                try:
                    if action == 'send_request':
                        if target_username in user_data['friends'] or \
                           target_username in user_data['requests'] or \
                           username in target_user_data.get('requests', []):
                            message = f"Friend request to '{target_username}' already pending or you are already friends."
                            message_type = "error"
                        elif target_username in user_data['blocked']:
                            message = f"You have blocked '{target_username}'. Unblock them first to send a request."
                            message_type = "error"
                        elif username in target_user_data.get('blocked', []):
                            message = f"You are blocked by '{target_username}'. Cannot send request."
                            message_type = "error"
                        else:
                            target_user_data['requests'].append(username)
                            save_user_data(target_user_data)
                            message = f"Friend request sent to '{target_username}'."
                            message_type = "success"

                    elif action == 'accept_request':
                        if target_username in user_data['requests']:
                            user_data['friends'].append(target_username)
                            user_data['requests'].remove(target_username)
                            
                            if username not in target_user_data['friends']:
                                target_user_data['friends'].append(username)
                            
                            save_user_data(user_data)
                            save_user_data(target_user_data)
                            message = f"Accepted friend request from '{target_username}'."
                            message_type = "success"
                        else:
                            message = f"No pending request from '{target_username}'."
                            message_type = "error"

                    elif action == 'decline_request':
                        if target_username in user_data['requests']:
                            user_data['requests'].remove(target_username)
                            save_user_data(user_data)
                            message = f"Declined friend request from '{target_username}'."
                            message_type = "success"
                        else:
                            message = f"No pending request from '{target_username}'."
                            message_type = "error"

                    elif action == 'remove_friend':
                        if target_username in user_data['friends']:
                            user_data['friends'].remove(target_username)
                            if username in target_user_data['friends']:
                                target_user_data['friends'].remove(username)
                            save_user_data(user_data)
                            save_user_data(target_user_data)
                            message = f"Removed '{target_username}' from friends."
                            message_type = "success"
                        else:
                            message = f"'{target_username}' is not in your friends list."
                            message_type = "error"

                    elif action == 'block_user':
                        if target_username not in user_data['blocked']:
                            user_data['blocked'].append(target_username)
                            if target_username in user_data['friends']:
                                user_data['friends'].remove(target_username)
                                if username in target_user_data['friends']:
                                    target_user_data['friends'].remove(username)
                            if target_username in user_data['requests']:
                                user_data['requests'].remove(target_username)
                            if username in target_user_data.get('requests', []):
                                target_user_data['requests'].remove(username)

                            save_user_data(user_data)
                            save_user_data(target_user_data)
                            message = f"Blocked '{target_username}'."
                            message_type = "success"
                        else:
                            message = f"'{target_username}' is already blocked."
                            message_type = "error"

                    elif action == 'unblock_user':
                        if target_username in user_data['blocked']:
                            user_data['blocked'].remove(target_username)
                            save_user_data(user_data)
                            message = f"Unblocked '{target_username}'."
                            message_type = "success"
                        else:
                            message = f"'{target_username}' is not blocked."
                            message_type = "error"

                    else:
                        message = "Invalid action."
                        message_type = "error"

                except Exception as e:
                    message = f"An error occurred: {e}"
                    message_type = "error"
                    app.logger.error(f"Error in friends route for user {username}: {e}")

    user_data = load_user_data(username) # Reload user data after any potential modifications
    return render_template('friends.html', 
                           current_user=current_user, 
                           user_data=user_data, 
                           message=message, 
                           message_type=message_type)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_data = load_user_data(current_user.username)
    current_settings = user_data.get('settings', {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'})
    message = None
    message_type = None

    if request.method == 'POST':
        new_primary = request.form.get('primary_color')
        new_accent = request.form.get('accent_color')

        if new_primary and new_accent:
            user_data['settings']['primary_color'] = new_primary
            user_data['settings']['accent_color'] = new_accent
            save_user_data(user_data)
            
            session['primary_color'] = new_primary
            session['accent_color'] = new_accent
            
            message = "Theme settings updated successfully!"
            message_type = "success"
        else:
            message = "Both colors are required."
            message_type = "error"

    current_settings = load_user_data(current_user.username).get('settings', {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'})
    return render_template('settings.html', 
                           current_user=current_user, 
                           settings=current_settings,
                           message=message,
                           message_type=message_type)

@app.route('/admin', methods=['GET', 'POST']) # Changed route to /admin
@login_required
def admin_page():
    if current_user.username != 'admin':
        abort(403) # Forbidden for non-admin users

    all_users_data = load_all_users_data()
    banned_emails = load_banned_emails()
    
    # Convert raw user data to User objects to leverage .is_timed_out and .timeout_until
    users_for_template = []
    for username, data in all_users_data.items():
        if username != 'admin': # Don't list admin for management actions on self
            users_for_template.append(User(username, username, data['email'], 
                                           data['password'], data.get('friends'), 
                                           data.get('requests'), data.get('blocked'), 
                                           data.get('chat_history'), data.get('settings'), 
                                           data.get('timeout_until')))

    message = None
    message_type = None

    if request.method == 'POST':
        action = request.form.get('action')
        target_username = request.form.get('target_username') # For user actions
        target_email = request.form.get('target_email') # For ban/unban email

        if action in ['delete_user', 'change_password', 'timeout', 'untimeout', 'ban_user']:
            if not target_username or target_username not in all_users_data:
                message = f"User '{target_username}' not found."
                message_type = "error"
            elif target_username == 'admin' and action not in ['change_password']:
                message = "Cannot perform this action on the admin user (except password change)."
                message_type = "error"
            else:
                try:
                    if action == 'delete_user':
                        user_to_delete_data = all_users_data.get(target_username)
                        if user_to_delete_data:
                            # Clean up references to target_username from other users' lists
                            for username_key, data in all_users_data.items():
                                if username_key != target_username: 
                                    if target_username in data.get('friends', []):
                                        data['friends'].remove(target_username)
                                    if target_username in data.get('requests', []):
                                        data['requests'].remove(target_username)
                                    if target_username in data.get('blocked', []):
                                        data['blocked'].remove(target_username)

                        del all_users_data[target_username] 
                        save_all_users_data(all_users_data)
                        message = f"User '{target_username}' deleted."
                        message_type = "success"
                    
                    elif action == 'change_password':
                        new_password = request.form.get('new_password')
                        if not new_password or len(new_password) < 6:
                            message = "New password must be at least 6 characters."
                            message_type = "error"
                        else:
                            all_users_data[target_username]['password'] = generate_password_hash(new_password)
                            save_all_users_data(all_users_data)
                            message = f"Password for '{target_username}' changed successfully."
                            message_type = "success"
                    
                    elif action == 'timeout':
                        minutes = int(request.form.get('minutes', 0))
                        if minutes > 0:
                            timeout_time = datetime.now() + timedelta(minutes=minutes)
                            all_users_data[target_username]['timeout_until'] = timeout_time.isoformat()
                            save_all_users_data(all_users_data)
                            message = f"User '{target_username}' timed out for {minutes} minutes."
                            message_type = "success"
                        else:
                            message = "Invalid timeout duration."
                            message_type = "error"

                    elif action == 'untimeout':
                        all_users_data[target_username]['timeout_until'] = None
                        save_all_users_data(all_users_data)
                        message = f"User '{target_username}' un-timed out."
                        message_type = "success"

                    elif action == 'ban_user':
                        user_to_ban = all_users_data.get(target_username)
                        if user_to_ban and user_to_ban['email'] not in banned_emails:
                            banned_emails.append(user_to_ban['email'])
                            save_banned_emails(banned_emails)
                            # Optionally delete the user as well upon banning
                            # del all_users_data[target_username] 
                            # save_all_users_data(all_users_data)
                            message = f"User '{target_username}' (email: {user_to_ban['email']}) banned."
                            message_type = "success"
                        else:
                            message = f"Email for '{target_username}' is already banned or user not found."
                            message_type = "error"

                except Exception as e:
                    message = f"An error occurred: {e}"
                    message_type = "error"
                    app.logger.error(f"Admin action error: {e}")

        elif action == 'unban_email': # Separate action for unbanning by email
            if target_email and target_email in banned_emails:
                banned_emails.remove(target_email)
                save_banned_emails(banned_emails)
                message = f"Email '{target_email}' unbanned."
                message_type = "success"
            else:
                message = f"Email '{target_email}' not found in banned list."
                message_type = "error"
        else:
            message = "Invalid admin action."
            message_type = "error"
    
    # Reload data for template after any POST action
    all_users_data = load_all_users_data()
    banned_emails = load_banned_emails()
    users_for_template = []
    for username, data in all_users_data.items():
        if username != 'admin':
            users_for_template.append(User(username, username, data['email'], 
                                           data['password'], data.get('friends'), 
                                           data.get('requests'), data.get('blocked'), 
                                           data.get('chat_history'), data.get('settings'), 
                                           data.get('timeout_until')))

    return render_template('admin.html', 
                           current_user=current_user, 
                           users=users_for_template, # Pass User objects
                           banned_list=banned_emails, # Pass raw banned emails
                           now=datetime.now(), # Pass current time for comparison in template
                           message=message, 
                           message_type=message_type,
                           show_login=False) # Always false, since Flask-Login handles it


# --- SocketIO Events ---
@socketio.on('join')
def on_join(data):
    username = current_user.username
    room = data['room']
    
    if current_user.is_timed_out:
        emit('error', {'message': f'You are temporarily timed out until {current_user.timeout_until.strftime("%Y-%m-%d %H:%M")}.'}, room=request.sid)
        return

    users_in_room = room.split('-')
    other_user = None
    if users_in_room[0] == username:
        other_user = users_in_room[1]
    elif users_in_room[1] == username:
        other_user = users_in_room[0]
    
    if not other_user: 
        emit('error', {'message': 'Invalid room format.'}, room=request.sid)
        return

    user_data = load_user_data(username)
    target_user_data = load_user_data(other_user) 

    if other_user not in user_data.get('friends', []):
        emit('error', {'message': f'You are not friends with {other_user}. Cannot join chat.'}, room=request.sid)
        return
    
    if target_user_data and username in target_user_data.get('blocked', []):
        emit('error', {'message': f'You are blocked by {other_user}. Cannot join chat.'}, room=request.sid)
        return

    join_room(room)
    app.logger.info(f'User {username} joined room: {room}')


@socketio.on('leave')
def on_leave(data):
    username = current_user.username
    room = data['room']
    leave_room(room)
    app.logger.info(f'User {username} left room: {room}')

@socketio.on('send_message')
def handle_message(data):
    username = current_user.username
    room = data['room']
    msg = data['msg']
    
    if current_user.is_timed_out:
        emit('error', {'message': f'You are temporarily timed out until {current_user.timeout_until.strftime("%Y-%m-%d %H:%M")}. Cannot send messages.'}, room=request.sid)
        return

    message_id = f"{username}_{int(time.time() * 1000)}" 
    timestamp = datetime.now().strftime('%H:%M')

    message_data = {
        'id': message_id,
        'username': username,
        'msg': msg,
        'time': timestamp,
        'room': room 
    }
    
    add_message_to_history(room, message_data)

    app.logger.info(f'Message from {username} in {room}: {msg}')
    emit('message', message_data, room=room)

@socketio.on('edit_message')
def handle_edit_message(data):
    username = current_user.username
    message_id = data['message_id']
    new_text = data['new_text']
    room = data['room']

    if current_user.is_timed_out:
        emit('error', {'message': f'You are temporarily timed out until {current_user.timeout_until.strftime("%Y-%m-%d %H:%M")}. Cannot edit messages.'}, room=request.sid)
        return

    user_data = load_user_data(username)
    chat_history = user_data.get('chat_history', {}).get(room, [])

    message_found = False
    updated_msg_content = new_text 
    for msg_obj in chat_history:
        if msg_obj.get('id') == message_id and msg_obj.get('username') == username:
            if new_text.strip() == "": 
                updated_msg_content = "<em>deleted message</em>"
            else:
                updated_msg_content = f"{new_text} <em>(edited)</em>"
            
            update_message_in_history(room, message_id, updated_msg_content)
            message_found = True
            break
    
    if message_found:
        emit('message_updated', {'id': message_id, 'new_text': updated_msg_content, 'room': room}, room=room)
        app.logger.info(f"User {username} edited message {message_id} in {room}.")
    else:
        emit('error', {'message': 'Message not found or you do not have permission to edit this message.'}, room=request.sid)

@socketio.on('delete_message')
def handle_delete_message(data):
    username = current_user.username
    message_id = data['message_id']
    room = data['room']

    if current_user.is_timed_out:
        emit('error', {'message': f'You are temporarily timed out until {current_user.timeout_until.strftime("%Y-%m-%d %H:%M")}. Cannot delete messages.'}, room=request.sid)
        return

    user_data = load_user_data(username)
    chat_history = user_data.get('chat_history', {}).get(room, [])

    message_found = False
    for msg_obj in chat_history:
        if msg_obj.get('id') == message_id and msg_obj.get('username') == username:
            delete_message_from_history(room, message_id) 
            message_found = True
            break
    
    if message_found:
        emit('message_updated', {'id': message_id, 'new_text': "<em>deleted message</em>", 'room': room}, room=room)
        app.logger.info(f"User {username} deleted message {message_id} in {room}.")
    else:
        emit('error', {'message': 'Message not found or you do not have permission to delete this message.'}, room=request.sid)


if __name__ == '__main__':
    # Initialize admin user if not exists (for testing)
    all_users = load_all_users_data()
    if 'admin' not in all_users:
        admin_password_hash = generate_password_hash('admin') # !!! CHANGE ADMIN PASSWORD FOR PRODUCTION !!!
        admin_data = {
            'username': 'admin',
            'email': 'admin@example.com',
            'password': admin_password_hash,
            'friends': [],
            'requests': [],
            'blocked': [],
            'chat_history': {},
            'settings': {'primary_color': '#ff3f81', 'accent_color': '#0f0f0f'}, # Admin can have a distinct theme
            'timeout_until': None
        }
        all_users['admin'] = admin_data
        save_all_users_data(all_users)
        print("Admin user created with username 'admin' and password 'adminpass'")
        print("!!! IMPORTANT: Change admin password immediately in app.py for production !!!")

    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, host="0.0.0.0", port=5000)