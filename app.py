import os
import json
import time
import secrets
import jwt # pip install PyJWT
from datetime import datetime, timedelta
from flask import Flask, request, jsonify # Removed render_template, redirect, url_for, flash, session, abort, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user # May still be useful for internal checks if session-based, but JWT is better for mobile
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import logging
import threading
from collections import defaultdict, deque
import base64 # For encoding image data if needed in API responses

# Configure logging
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
app.config['SECRET_KEY'] = 'YOUR_VERY_SECRET_KEY' # Use a strong, unique secret key
app.config['USER_DATA_FILE'] = 'users.json'
app.config['BANNED_EMAILS_FILE'] = 'banned_emails.json'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['JWT_SECRET_KEY'] = 'YOUR_JWT_SECRET_KEY' # Separate secret for JWT tokens

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
# login_manager = LoginManager() # Commenting out Flask-Login for now, use JWT
# login_manager.init_app(app)
# login_manager.login_view = 'login'

user_sids = {}
active_calls = {}

# Rate limiting
user_message_times = defaultdict(lambda: deque(maxlen=20))
RATE_LIMIT_MESSAGES = 10
RATE_LIMIT_WINDOW = 5

# File lock for thread-safe operations
file_lock = threading.Lock()

def generate_csrf_token():
    # CSRF is less relevant for API-only backends accessed by native apps
    # Can be removed if relying on JWT
    pass

# --- JWT Authentication Functions ---
def create_jwt_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24) # Token expires in 24 hours
    }
    token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
    return token

def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# --- Rate Limiting Functions ---
def check_rate_limit(username):
    now = time.time()
    user_times = user_message_times[username]
    while user_times and user_times[0] < now - RATE_LIMIT_WINDOW:
        user_times.popleft()
    if len(user_times) >= RATE_LIMIT_MESSAGES:
        return False
    user_times.append(now)
    return True

# --- User Management (Simplified, still using User class for data structure) ---
class User(UserMixin):
    def __init__(self, id, username, email, password_hash, friends=None, requests=None, blocked=None, chat_history=None, settings=None, timeout_until=None, status='offline', last_seen=None):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.friends = friends if friends is not None else []
        self.requests = requests if requests is not None else []
        self.blocked = blocked if blocked is not None else []
        self.chat_history = chat_history if chat_history is not None else {}
        self.settings = settings if settings is not None else {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'}
        self.timeout_until = datetime.fromisoformat(timeout_until) if timeout_until else None
        self.status = status
        self.last_seen = datetime.fromisoformat(last_seen) if last_seen else datetime.now()

    def to_dict(self, include_password_hash=False):
        d = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'friends': self.friends,
            'requests': self.requests,
            'blocked': self.blocked,
            'settings': self.settings,
            'timeout_until': self.timeout_until.isoformat() if self.timeout_until else None,
            'status': self.status,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }
        if include_password_hash:
            d['password_hash'] = self.password_hash
        return d

    @property
    def is_timed_out(self):
        return self.timeout_until and self.timeout_until > datetime.now()

    @staticmethod
    def get(user_id):
        user_data = load_user_data(user_id)
        if user_data:
            return User(
                user_data['username'],  # Use username as id for simplicity here
                user_data['username'],
                user_data['email'],
                user_data['password'],
                user_data.get('friends'),
                user_data.get('requests'),
                user_data.get('blocked'),
                user_data.get('chat_history'),
                user_data.get('settings'),
                user_data.get('timeout_until'),
                user_data.get('status', 'offline'),
                user_data.get('last_seen')
            )
        return None

# --- Data Persistence Functions (Remain largely the same) ---
def load_all_users_data():
    with file_lock:
        try:
            if not os.path.exists(app.config['USER_DATA_FILE']):
                return {}
            with open(app.config['USER_DATA_FILE'], 'r') as f:
                data = json.load(f)
                return data
        except json.JSONDecodeError as e:
            app.logger.error(f"JSON decode error in {app.config['USER_DATA_FILE']}: {e}")
            return {}
        except Exception as e:
            app.logger.error(f"Error loading user data: {e}")
            return {}

def save_all_users_data(all_users_data):
    with file_lock:
        try:
            temp_file = app.config['USER_DATA_FILE'] + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(all_users_data, f, indent=4)
            os.replace(temp_file, app.config['USER_DATA_FILE'])
            return True
        except Exception as e:
            app.logger.error(f"Error saving user data: {e}")
            return False

def load_user_data(username):
    all_users = load_all_users_data()
    return all_users.get(username)

def save_user_data(user_data_dict):
    all_users = load_all_users_data()
    if 'status' not in user_data_dict:
        user_data_dict['status'] = 'offline'
    if 'last_seen' not in user_data_dict:
        user_data_dict['last_seen'] = datetime.now().isoformat()
    all_users[user_data_dict['username']] = user_data_dict
    return save_all_users_data(all_users)

def get_user_by_username_or_email(login_field):
    all_users = load_all_users_data()
    for username, data in all_users.items():
        if username == login_field or data['email'] == login_field:
            return User(data['username'], data['username'], data['email'],
                        data['password'], data.get('friends'),
                        data.get('requests'), data.get('blocked'),
                        data.get('chat_history'), data.get('settings'),
                        data.get('timeout_until'),
                        data.get('status', 'offline'),
                        data.get('last_seen'))
    return None

def add_message_to_history(room, message_data):
    try:
        all_users = load_all_users_data()
        user1, user2 = room.split('-')
        modified = False
        for user_key in [user1, user2]:
            if user_key in all_users:
                if 'chat_history' not in all_users[user_key]:
                    all_users[user_key]['chat_history'] = {}
                if room not in all_users[user_key]['chat_history']:
                    all_users[user_key]['chat_history'][room] = []
                if len(all_users[user_key]['chat_history'][room]) >= 1000:
                    all_users[user_key]['chat_history'][room] = all_users[user_key]['chat_history'][room][-500:]
                all_users[user_key]['chat_history'][room].append(message_data)
                modified = True
        if modified:
            return save_all_users_data(all_users)
        return False
    except Exception as e:
        app.logger.error(f"Error adding message to history: {e}")
        return False

def update_message_in_history(room, message_id, new_text):
    try:
        all_users = load_all_users_data()
        user1, user2 = room.split('-')
        for user_key in [user1, user2]:
            if user_key in all_users and 'chat_history' in all_users[user_key] and room in all_users[user_key]['chat_history']:
                for msg in all_users[user_key]['chat_history'][room]:
                    if msg.get('id') == message_id:
                        msg['msg'] = new_text
                        break
        return save_all_users_data(all_users)
    except Exception as e:
        app.logger.error(f"Error updating message: {e}")
        return False

def delete_message_from_history(room, message_id):
    try:
        all_users = load_all_users_data()
        user1, user2 = room.split('-')
        for user_key in [user1, user2]:
            if user_key in all_users and 'chat_history' in all_users[user_key] and room in all_users[user_key]['chat_history']:
                for msg in all_users[user_key]['chat_history'][room]:
                    if msg.get('id') == message_id:
                        msg['msg'] = "<em>deleted message</em>"
                        break
        return save_all_users_data(all_users)
    except Exception as e:
        app.logger.error(f"Error deleting message: {e}")
        return False

def get_room_history(room_name, username):
    try:
        user_data = load_user_data(username)
        if user_data and 'chat_history' in user_data and room_name in user_data['chat_history']:
            return user_data['chat_history'][room_name]
        return []
    except Exception as e:
        app.logger.error(f"Error getting room history: {e}")
        return []

def update_user_status(username, status):
    try:
        user_data = load_user_data(username)
        if user_data:
            user_data['status'] = status
            user_data['last_seen'] = datetime.now().isoformat()
            return save_user_data(user_data)
        return False
    except Exception as e:
        app.logger.error(f"Error updating user status: {e}")
        return False

def get_user_status(username):
    try:
        user_data = load_user_data(username)
        if user_data:
            return user_data.get('status', 'offline'), user_data.get('last_seen')
        return 'offline', None
    except Exception as e:
        app.logger.error(f"Error getting user status: {e}")
        return 'offline', None

def get_all_users_statuses():
    try:
        all_users = load_all_users_data()
        statuses = {}
        for username, data in all_users.items():
            statuses[username] = {
                'status': data.get('status', 'offline'),
                'last_seen': data.get('last_seen')
            }
        return statuses
    except Exception as e:
        app.logger.error(f"Error getting all statuses: {e}")
        return {}

def load_banned_emails():
    try:
        if not os.path.exists(app.config['BANNED_EMAILS_FILE']):
            return []
        with open(app.config['BANNED_EMAILS_FILE'], 'r') as f:
            return json.load(f)
    except Exception as e:
        app.logger.warning(f"Error loading banned emails: {e}")
        return []

def save_banned_emails(banned_list):
    try:
        with open(app.config['BANNED_EMAILS_FILE'], 'w') as f:
            json.dump(banned_list, f, indent=4)
        return True
    except Exception as e:
        app.logger.error(f"Error saving banned emails: {e}")
        return False

def is_email_banned(email):
    banned_list = load_banned_emails()
    return email in banned_list

# --- Authentication Decorator ---
def token_required(f):
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # Expect token in format "Bearer <token_string>"
            token = token.split(" ")[1] if " " in token else None
            if not token:
                 return jsonify({'message': 'Invalid token format!'}), 401
            user_id = decode_jwt_token(token)
            if not user_id:
                return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 401

        # Attach user object to request context if needed, or pass user_id
        # For simplicity, we'll just get the user object here if needed later
        current_user_obj = User.get(user_id)
        if not current_user_obj:
            return jsonify({'message': 'User not found!'}), 401

        # Store user in a way accessible to the route function
        # Flask's g object is often used for this
        from flask import g
        g.current_user = current_user_obj

        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ # Required for Flask
    return decorated_function

# --- API Routes ---
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    all_users = load_all_users_data()
    banned_emails = load_banned_emails()

    if not username or not email or not password:
        return jsonify({'message': 'All fields are required.'}), 400

    if len(username) < 3:
        return jsonify({'message': 'Username must be at least 3 characters long.'}), 400

    if not "@" in email or "." not in email:
        return jsonify({'message': 'Invalid email format.'}), 400

    if len(password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters long.'}), 400

    if username in all_users:
        return jsonify({'message': 'Username already exists.'}), 409

    for user_data in all_users.values():
        if user_data['email'] == email:
            return jsonify({'message': 'Email already registered.'}), 409

    if email in banned_emails:
        return jsonify({'message': 'This email address is banned from registration.'}), 403

    hashed_password = generate_password_hash(password)
    new_user_data = {
        'username': username,
        'email': email,
        'password': hashed_password,
        'friends': [],
        'requests': [],
        'blocked': [],
        'chat_history': {},
        'settings': {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'},
        'timeout_until': None,
        'status': 'offline',
        'last_seen': datetime.now().isoformat()
    }
    all_users[username] = new_user_data
    if save_all_users_data(all_users):
        return jsonify({'message': 'Registration successful!'}), 201
    else:
        return jsonify({'message': 'Registration failed. Please try again.'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    login_field = data.get('login_field') # Can be username or email
    password = data.get('password')

    user = get_user_by_username_or_email(login_field)
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Invalid username/email or password.'}), 401

    if is_email_banned(user.email):
        return jsonify({'message': 'Your account is banned.'}), 403

    if user.is_timed_out:
        return jsonify({'message': f'Your account is temporarily timed out until {user.timeout_until.strftime("%Y-%m-%d %H:%M")}.', 'timeout_expires': user.timeout_until.isoformat()}), 403

    # Update status and create token
    update_user_status(user.username, 'online')
    token = create_jwt_token(user.id)

    return jsonify({'message': 'Logged in successfully!', 'token': token, 'user': user.to_dict()}), 200

@app.route('/api/logout', methods=['POST'])
@token_required
def api_logout():
    # Flask-Login's logout_user() is not used here
    # Just update status
    update_user_status(g.current_user.username, 'offline')
    return jsonify({'message': 'Logged out successfully!'}), 200

@app.route('/api/chat/rooms/<room_name>/messages', methods=['GET'])
@token_required
def api_get_history(room_name):
    current_user_obj = g.current_user
    try:
        user1, user2 = room_name.split('-')
        if not (current_user_obj.username == user1 or current_user_obj.username == user2):
            return jsonify({'message': 'Unauthorized to view this chat history'}), 403

        current_user_data = load_user_data(current_user_obj.username)
        if not current_user_data:
            return jsonify({'message': 'User data not found'}), 404

        target_username = user2 if current_user_obj.username == user1 else user1
        if target_username not in current_user_data.get('friends', []):
            target_user_data = load_user_data(target_username)
            if target_user_data and current_user_obj.username in target_user_data.get('blocked', []):
                return jsonify({'message': f'You are blocked by {target_username}. Cannot view chat history.'}), 403
            return jsonify({'message': 'You are not friends with this user. Cannot view chat history.'}), 403

        history_messages = get_room_history(room_name, current_user_obj.username)
        return jsonify({'messages': history_messages}), 200
    except ValueError: # Invalid room format
        return jsonify({'message': 'Invalid room format'}), 400
    except Exception as e:
        app.logger.error(f"Error loading history: {e}")
        return jsonify({'message': 'Failed to load history'}), 500

@app.route('/api/upload_file', methods=['POST'])
@token_required
def api_upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'message': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'message': 'No selected file'}), 400
        if file:
            filename = secure_filename(file.filename)
            timestamp = int(time.time())
            unique_filename = f"{timestamp}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            # Return URL relative to the server's file serving endpoint
            file_url = f"/uploads/{unique_filename}"
            return jsonify({'url': file_url}), 200
    except Exception as e:
        app.logger.error(f"Error saving file: {e}")
        return jsonify({'message': f'Failed to save file: {str(e)}'}), 500

# Serve uploaded files (still needed for the API to provide the file URL)
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/friends', methods=['GET', 'POST'])
@token_required
def api_friends():
    current_user_obj = g.current_user
    username = current_user_obj.username
    user_data = load_user_data(username)

    if request.method == 'POST':
        data = request.get_json()
        action = data.get('action')
        target_username = data.get('target_username')

        if not target_username:
            return jsonify({'message': "Target username is required."}), 400
        if target_username == username:
            return jsonify({'message': "You cannot perform this action on yourself."}), 400

        target_user_data = load_user_data(target_username)
        if not target_user_data:
            return jsonify({'message': f"User '{target_username}' not found."}), 404

        try:
            if action == 'send_request':
                if target_username in user_data['friends'] or \
                   target_username in user_data['requests'] or \
                   username in target_user_data.get('requests', []):
                    return jsonify({'message': f"Friend request to '{target_username}' already pending or you are already friends."}), 400
                if target_username in user_data['blocked']:
                    return jsonify({'message': f"You have blocked '{target_username}'. Unblock them first to send a request."}), 400
                if username in target_user_data.get('blocked', []):
                    return jsonify({'message': f"You are blocked by '{target_username}'. Cannot send request."}), 403

                target_user_data['requests'].append(username)
                if save_user_data(target_user_data):
                    return jsonify({'message': f"Friend request sent to '{target_username}'."}), 200
                else:
                    return jsonify({'message': "Failed to send request. Please try again."}), 500

            elif action == 'accept_request':
                if target_username in user_data['requests']:
                    user_data['friends'].append(target_username)
                    user_data['requests'].remove(target_username)
                    if username not in target_user_data['friends']:
                        target_user_data['friends'].append(username)
                    if save_user_data(user_data) and save_user_data(target_user_data):
                        return jsonify({'message': f"Accepted friend request from '{target_username}'."}), 200
                    else:
                        return jsonify({'message': "Failed to accept request. Please try again."}), 500
                else:
                    return jsonify({'message': f"No pending request from '{target_username}'."}), 400

            elif action == 'decline_request':
                if target_username in user_data['requests']:
                    user_data['requests'].remove(target_username)
                    if save_user_data(user_data):
                        return jsonify({'message': f"Declined friend request from '{target_username}'."}), 200
                    else:
                        return jsonify({'message': "Failed to decline request."}), 500
                else:
                    return jsonify({'message': f"No pending request from '{target_username}'."}), 400

            elif action == 'remove_friend':
                if target_username in user_data['friends']:
                    user_data['friends'].remove(target_username)
                    if username in target_user_data['friends']:
                        target_user_data['friends'].remove(username)
                    if save_user_data(user_data) and save_user_data(target_user_data):
                        return jsonify({'message': f"Removed '{target_username}' from friends."}), 200
                    else:
                        return jsonify({'message': "Failed to remove friend."}), 500
                else:
                    return jsonify({'message': f"'{target_username}' is not in your friends list."}), 400

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
                    if save_user_data(user_data) and save_user_data(target_user_data):
                        return jsonify({'message': f"Blocked '{target_username}'."}), 200
                    else:
                        return jsonify({'message': "Failed to block user."}), 500
                else:
                    return jsonify({'message': f"'{target_username}' is already blocked."}), 400

            elif action == 'unblock_user':
                if target_username in user_data['blocked']:
                    user_data['blocked'].remove(target_username)
                    if save_user_data(user_data):
                        return jsonify({'message': f"Unblocked '{target_username}'."}), 200
                    else:
                        return jsonify({'message': "Failed to unblock user."}), 500
                else:
                    return jsonify({'message': f"'{target_username}' is not blocked."}), 400

            else:
                return jsonify({'message': "Invalid action."}), 400

        except Exception as e:
            app.logger.error(f"Error in friends API for user {username}: {e}")
            return jsonify({'message': f"An error occurred: {e}"}), 500

    # GET request - return friend list and requests
    user_data = load_user_data(username)
    return jsonify({
        'friends': user_data.get('friends', []),
        'requests': user_data.get('requests', []),
        'blocked': user_data.get('blocked', [])
    }), 200

@app.route('/api/settings', methods=['GET', 'PUT'])
@token_required
def api_settings():
    current_user_obj = g.current_user
    user_data = load_user_data(current_user_obj.username)

    if request.method == 'PUT':
        data = request.get_json()
        new_primary = data.get('primary_color')
        new_accent = data.get('accent_color')

        if new_primary and new_accent:
            user_data['settings']['primary_color'] = new_primary
            user_data['settings']['accent_color'] = new_accent
            if save_user_data(user_data):
                return jsonify({'message': "Theme settings updated successfully!"}), 200
            else:
                return jsonify({'message': "Failed to update settings. Please try again."}), 500
        else:
            return jsonify({'message': "Both colors are required."}), 400

    # GET request
    current_settings = user_data.get('settings', {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'})
    return jsonify({'settings': current_settings}), 200

@app.route('/api/admin', methods=['GET', 'POST'])
@token_required
def api_admin_page():
    current_user_obj = g.current_user
    if current_user_obj.username != 'admin':
        return jsonify({'message': 'Forbidden'}), 403

    all_users_data = load_all_users_data()
    banned_emails = load_banned_emails()
    users_for_response = []
    for username, data in all_users_data.items():
        if username != 'admin':
            users_for_response.append({
                'username': data['username'],
                'email': data['email'],
                'status': data.get('status', 'offline'),
                'last_seen': data.get('last_seen'),
                'timeout_until': data.get('timeout_until')
            })

    if request.method == 'POST':
        data = request.get_json()
        action = data.get('action')
        target_username = data.get('target_username')
        target_email = data.get('target_email')

        if action in ['delete_user', 'change_password', 'timeout', 'untimeout', 'ban_user']:
            if not target_username or target_username not in all_users_data:
                return jsonify({'message': f"User '{target_username}' not found."}), 404
            if target_username == 'admin' and action not in ['change_password']:
                return jsonify({'message': "Cannot perform this action on the admin user (except password change)."}), 403

            try:
                if action == 'delete_user':
                    user_to_delete_data = all_users_data.get(target_username)
                    if user_to_delete_data:
                        for username_key, data in all_users_data.items():
                            if username_key != target_username:
                                if target_username in data.get('friends', []):
                                    data['friends'].remove(target_username)
                                if target_username in data.get('requests', []):
                                    data['requests'].remove(target_username)
                                if target_username in data.get('blocked', []):
                                    data['blocked'].remove(target_username)
                    del all_users_data[target_username]
                    if save_all_users_data(all_users_data):
                        return jsonify({'message': f"User '{target_username}' deleted."}), 200
                    else:
                        return jsonify({'message': "Failed to delete user."}), 500

                elif action == 'change_password':
                    new_password = data.get('new_password')
                    if not new_password or len(new_password) < 6:
                        return jsonify({'message': "New password must be at least 6 characters."}), 400
                    all_users_data[target_username]['password'] = generate_password_hash(new_password)
                    if save_all_users_data(all_users_data):
                        return jsonify({'message': f"Password for '{target_username}' changed successfully."}), 200
                    else:
                        return jsonify({'message': "Failed to change password."}), 500

                elif action == 'timeout':
                    minutes = int(data.get('minutes', 0))
                    if minutes > 0:
                        timeout_time = datetime.now() + timedelta(minutes=minutes)
                        all_users_data[target_username]['timeout_until'] = timeout_time.isoformat()
                        if save_all_users_data(all_users_data):
                            return jsonify({'message': f"User '{target_username}' timed out for {minutes} minutes."}), 200
                        else:
                            return jsonify({'message': "Failed to timeout user."}), 500
                    else:
                        return jsonify({'message': "Invalid timeout duration."}), 400

                elif action == 'untimeout':
                    all_users_data[target_username]['timeout_until'] = None
                    if save_all_users_data(all_users_data):
                        return jsonify({'message': f"User '{target_username}' un-timed out."}), 200
                    else:
                        return jsonify({'message': "Failed to untimeout user."}), 500

                elif action == 'ban_user':
                    user_to_ban = all_users_data.get(target_username)
                    if user_to_ban and user_to_ban['email'] not in banned_emails:
                        banned_emails.append(user_to_ban['email'])
                        if save_banned_emails(banned_emails):
                            return jsonify({'message': f"User '{target_username}' (email: {user_to_ban['email']}) banned."}), 200
                        else:
                            return jsonify({'message': "Failed to ban user."}), 500
                    else:
                        return jsonify({'message': f"Email for '{target_username}' is already banned or user not found."}), 400

            except ValueError: # For int(minutes) conversion
                 return jsonify({'message': "Invalid input for timeout duration."}), 400
            except Exception as e:
                app.logger.error(f"Admin action error: {e}")
                return jsonify({'message': f"An error occurred: {e}"}), 500

        elif action == 'unban_email':
            if target_email and target_email in banned_emails:
                banned_emails.remove(target_email)
                if save_banned_emails(banned_emails):
                    return jsonify({'message': f"Email '{target_email}' unbanned."}), 200
                else:
                    return jsonify({'message': "Failed to unban email."}), 500
            else:
                return jsonify({'message': f"Email '{target_email}' not found in banned list."}), 404
        else:
            return jsonify({'message': "Invalid admin action."}), 400

    # GET request - return user list and banned emails
    return jsonify({
        'users': users_for_response,
        'banned_emails': banned_emails
    }), 200

# --- SocketIO Events (Adapted for API client) ---
@socketio.on('connect')
def handle_connect():
    # Authentication for SocketIO needs to happen here, often via a query parameter
    auth_token = request.args.get('token') # Client sends token in query string
    if auth_token:
        user_id = decode_jwt_token(auth_token)
        if user_id:
            user = User.get(user_id)
            if user and not user.is_timed_out:
                username = user.username
                if username not in user_sids:
                    user_sids[username] = []
                user_sids[username].append(request.sid)
                update_user_status(username, 'online')
                app.logger.info(f'SocketIO: User {username} connected')
                return True # Allow connection
    # If token is invalid, missing, or user is timed out, deny connection
    app.logger.warning(f'SocketIO: Connection denied for SID {request.sid}')
    return False # Deny connection

@socketio.on('disconnect')
def handle_disconnect():
    # Find the user associated with the disconnected SID
    disconnected_user = None
    for user, sids in user_sids.items():
        if request.sid in sids:
            sids.remove(request.sid)
            disconnected_user = user
            if not sids: # No more SIDs for this user
                del user_sids[user]
                update_user_status(user, 'offline')
                # Notify friends of disconnection
                user_data = load_user_data(user)
                if user_data:
                    for friend_username in user_data.get('friends', []):
                        if friend_username in user_sids:
                            for friend_sid in user_sids[friend_username]:
                                emit('user_status_update', {
                                    'username': user,
                                    'status': 'offline'
                                }, room=friend_sid)
            break
    if disconnected_user:
        app.logger.info(f'SocketIO: User {disconnected_user} disconnected')

@socketio.on('join')
def on_join(data):
    try:
        # Get user from the connection (already authenticated in connect)
        username = None
        for user, sids in user_sids.items():
            if request.sid in sids:
                username = user
                break
        if not username:
             emit('error', {'message': 'Authentication error during join.'})
             return

        room = data['room']
        user_obj = User.get(username) # Get user object to check timeout
        if user_obj and user_obj.is_timed_out:
            emit('error', {'message': f'You are temporarily timed out until {user_obj.timeout_until.strftime("%Y-%m-%d %H:%M")}.'})
            return

        users_in_room = room.split('-')
        other_user = None
        if users_in_room[0] == username:
            other_user = users_in_room[1]
        elif users_in_room[1] == username:
            other_user = users_in_room[0]

        if not other_user:
            emit('error', {'message': 'Invalid room format.'})
            return

        user_data = load_user_data(username)
        target_user_data = load_user_data(other_user)
        if not user_data or not target_user_data:
            emit('error', {'message': 'User data not found.'})
            return

        if other_user not in user_data.get('friends', []):
            emit('error', {'message': f'You are not friends with {other_user}. Cannot join chat.'})
            return

        if username in target_user_data.get('blocked', []):
            emit('error', {'message': f'You are blocked by {other_user}. Cannot join chat.'})
            return

        join_room(room)
        app.logger.info(f'SocketIO: User {username} joined room: {room}')

        # Notify friends of online status if needed (SocketIO handles real-time updates)
        # The status update via SocketIO is handled in connect/disconnect

    except Exception as e:
        app.logger.error(f"Error in on_join: {e}")
        emit('error', {'message': 'Failed to join room.'})

@socketio.on('leave')
def on_leave(data):
    try:
        username = None
        for user, sids in user_sids.items():
            if request.sid in sids:
                username = user
                break
        room = data['room']
        leave_room(room)
        app.logger.info(f'SocketIO: User {username} left room: {room}')
    except Exception as e:
        app.logger.error(f"Error in on_leave: {e}")

@socketio.on('send_message')
def handle_message(data):
    try:
        username = None
        for user, sids in user_sids.items():
            if request.sid in sids:
                username = user
                break
        if not username:
             emit('error', {'message': 'Authentication error during send_message.'})
             return

        user_obj = User.get(username) # Get user object to check timeout
        if user_obj and user_obj.is_timed_out:
            emit('error', {'message': f'You are temporarily timed out until {user_obj.timeout_until.strftime("%Y-%m-%d %H:%M")}. Cannot send messages.'})
            return

        room = data['room']
        msg = data['msg']
        reply_to = data.get('reply_to')

        if not check_rate_limit(username):
            emit('error', {'message': f'You are sending messages too quickly. Please wait a moment.'})
            app.logger.warning(f"Rate limit exceeded for user {username}")
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
        if reply_to:
            message_data['reply_to'] = reply_to

        if not add_message_to_history(room, message_data):
            app.logger.error(f"Failed to save message to history for {username} in {room}")
            emit('error', {'message': 'Failed to save message. Please try again.'})
            return

        app.logger.info(f'SocketIO Message from {username} in {room}: {msg}')
        emit('message', message_data, room=room)

    except Exception as e:
        app.logger.error(f"Error in handle_message: {e}")
        emit('error', {'message': 'Failed to send message.'})

# Other SocketIO events (edit_message, delete_message, typing_start, etc.) follow the same pattern:
# 1. Get username from user_sids
# 2. Check timeout if necessary
# 3. Perform action
# 4. Emit result via SocketIO

@socketio.on('edit_message')
def handle_edit_message(data):
    try:
        username = None
        for user, sids in user_sids.items():
            if request.sid in sids:
                username = user
                break
        if not username:
             emit('error', {'message': 'Authentication error during edit_message.'})
             return

        user_obj = User.get(username)
        if user_obj and user_obj.is_timed_out:
            emit('error', {'message': f'You are temporarily timed out until {user_obj.timeout_until.strftime("%Y-%m-%d %H:%M")}. Cannot edit messages.'})
            return

        message_id = data['message_id']
        new_text = data['new_text']
        room = data['room']

        user_data = load_user_data(username)
        if not user_data:
            emit('error', {'message': 'User data not found.'})
            return

        chat_history = user_data.get('chat_history', {}).get(room, [])
        message_found = False
        updated_msg_content = new_text
        for msg_obj in chat_history:
            if msg_obj.get('id') == message_id and msg_obj.get('username') == username:
                if new_text.strip() == "":
                    updated_msg_content = "<em>deleted message</em>"
                else:
                    updated_msg_content = f"{new_text} <em>(edited)</em>"
                if not update_message_in_history(room, message_id, updated_msg_content):
                    emit('error', {'message': 'Failed to update message.'})
                    return
                message_found = True
                break

        if message_found:
            emit('message_updated', {'id': message_id, 'new_text': updated_msg_content, 'room': room}, room=room)
            app.logger.info(f"User {username} edited message {message_id} in {room}.")
        else:
            emit('error', {'message': 'Message not found or you do not have permission to edit this message.'})

    except Exception as e:
        app.logger.error(f"Error in handle_edit_message: {e}")
        emit('error', {'message': 'Failed to edit message.'})

@socketio.on('delete_message')
def handle_delete_message(data):
    try:
        username = None
        for user, sids in user_sids.items():
            if request.sid in sids:
                username = user
                break
        if not username:
             emit('error', {'message': 'Authentication error during delete_message.'})
             return

        user_obj = User.get(username)
        if user_obj and user_obj.is_timed_out:
            emit('error', {'message': f'You are temporarily timed out until {user_obj.timeout_until.strftime("%Y-%m-%d %H:%M")}. Cannot delete messages.'})
            return

        message_id = data['message_id']
        room = data['room']

        user_data = load_user_data(username)
        if not user_data:
            emit('error', {'message': 'User data not found.'})
            return

        chat_history = user_data.get('chat_history', {}).get(room, [])
        message_found = False
        for msg_obj in chat_history:
            if msg_obj.get('id') == message_id and msg_obj.get('username') == username:
                if not delete_message_from_history(room, message_id):
                    emit('error', {'message': 'Failed to delete message.'})
                    return
                message_found = True
                break

        if message_found:
            emit('message_updated', {'id': message_id, 'new_text': "<em>deleted message</em>", 'room': room}, room=room)
            app.logger.info(f"User {username} deleted message {message_id} in {room}.")
        else:
            emit('error', {'message': 'Message not found or you do not have permission to delete this message.'})

    except Exception as e:
        app.logger.error(f"Error in handle_delete_message: {e}")
        emit('error', {'message': 'Failed to delete message.'})

@socketio.on('typing_start')
def handle_typing_start(data):
    try:
        room = data['room']
        username = None
        for user, sids in user_sids.items():
            if request.sid in sids:
                username = user
                break
        user_obj = User.get(username)
        if user_obj and user_obj.is_timed_out:
            return # Silently ignore if timed out
        emit('user_typing', {'username': username, 'is_typing': True}, room=room, include_self=False)
    except Exception as e:
        app.logger.error(f"Error in handle_typing_start: {e}")

@socketio.on('typing_stop')
def handle_typing_stop(data):
    try:
        room = data['room']
        username = None
        for user, sids in user_sids.items():
            if request.sid in sids:
                username = user
                break
        user_obj = User.get(username)
        if user_obj and user_obj.is_timed_out:
            return # Silently ignore if timed out
        emit('user_typing', {'username': username, 'is_typing': False}, room=room, include_self=False)
    except Exception as e:
        app.logger.error(f"Error in handle_typing_stop: {e}")

@socketio.on('request_statuses')
def handle_request_statuses():
    try:
        username = None
        for user, sids in user_sids.items():
            if request.sid in sids:
                username = user
                break
        all_statuses = get_all_users_statuses()
        user_data = load_user_data(username)
        if user_data:
            friends = user_data.get('friends', [])
            friend_statuses = {k: v for k, v in all_statuses.items() if k in friends}
            emit('all_statuses', friend_statuses)
    except Exception as e:
        app.logger.error(f"Error in handle_request_statuses: {e}")

# Call events follow the same pattern, using user_sids to get the caller's username
# and checking permissions (e.g., friends only) based on that.

@socketio.on('call_user')
def handle_call_user(data):
    try:
        caller = None
        for user, sids in user_sids.items():
            if request.sid in sids:
                caller = user
                break
        if not caller:
             emit('error', {'message': 'Authentication error during call_user.'})
             return

        user_obj = User.get(caller)
        if user_obj and user_obj.is_timed_out:
            emit('error', {'message': 'You are timed out and cannot make calls.'})
            return

        receiver = data['receiver']
        call_type = data['type']
        room = data['room']

        user_data = load_user_data(caller)
        if not user_data or receiver not in user_data.get('friends', []):
            emit('error', {'message': 'You can only call friends.'})
            return

        if receiver not in user_sids:
            emit('error', {'message': f'{receiver} is not online.'})
            return

        if room in active_calls:
            emit('error', {'message': 'There is already an active call.'})
            return

        for receiver_sid in user_sids[receiver]:
            emit('incoming_call', {
                'caller': caller,
                'room': room,
                'type': call_type
            }, room=receiver_sid)

        app.logger.info(f'{caller} is calling {receiver} ({call_type})')

    except Exception as e:
        app.logger.error(f"Error in handle_call_user: {e}")
        emit('error', {'message': 'Failed to initiate call.'})

# ... (handle_answer_call, handle_reject_call, handle_end_call, handle_webrtc_... follow the same pattern)

if __name__ == '__main__':
    all_users = load_all_users_data()
    if 'admin' not in all_users:
        admin_password_hash = generate_password_hash('admin')
        admin_data = {
            'username': 'admin',
            'email': 'admin@example.com',
            'password': admin_password_hash,
            'friends': [],
            'requests': [],
            'blocked': [],
            'chat_history': {},
            'settings': {'primary_color': '#ff3f81', 'accent_color': '#0f0f0f'},
            'timeout_until': None,
            'status': 'offline',
            'last_seen': datetime.now().isoformat()
        }
        all_users['admin'] = admin_data
        save_all_users_data(all_users)
        print("Admin user created with username 'admin' and password 'admin'")
        print("!!! IMPORTANT: Change admin password immediately in app.py for production !!!")

    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, host="0.0.0.0", port=5000)
