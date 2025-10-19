import os
import json
import time
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import logging
import threading
from collections import defaultdict, deque

# Configure logging
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
app.config['SECRET_KEY'] = 'YOUR_VERY_SECRET_KEY'
app.config['USER_DATA_FILE'] = 'users.json'
app.config['BANNED_EMAILS_FILE'] = 'banned_emails.json'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROFILE_PICS_FOLDER'] = 'profile_pics'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['GROUP_CHATS_FILE'] = 'group_chats.json'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
if not os.path.exists(app.config['PROFILE_PICS_FOLDER']):
    os.makedirs(app.config['PROFILE_PICS_FOLDER'])

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

user_sids = {}
active_calls = {}

# Rate limiting
user_message_times = defaultdict(lambda: deque(maxlen=20))
RATE_LIMIT_MESSAGES = 10
RATE_LIMIT_WINDOW = 5
MESSAGES_PER_PAGE = 50

# File lock for thread-safe operations
file_lock = threading.Lock()

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# --- Rate Limiting Functions ---
def check_rate_limit(username):
    """Check if user is within rate limits"""
    now = time.time()
    user_times = user_message_times[username]
    
    while user_times and user_times[0] < now - RATE_LIMIT_WINDOW:
        user_times.popleft()
    
    if len(user_times) >= RATE_LIMIT_MESSAGES:
        return False
    
    user_times.append(now)
    return True

# --- User Management (Flask-Login) ---
class User(UserMixin):
    def __init__(self, id, username, email, password_hash, friends=None, requests=None, blocked=None, 
                 chat_history=None, settings=None, timeout_until=None, status='offline', last_seen=None, 
                 profile_picture=None):
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
        self.profile_picture = profile_picture

    def to_dict(self):
        return {
            'username': self.username,
            'email': self.email,
            'password': self.password_hash,
            'friends': self.friends,
            'requests': self.requests,
            'blocked': self.blocked,
            'chat_history': self.chat_history,
            'settings': self.settings,
            'timeout_until': self.timeout_until.isoformat() if self.timeout_until else None,
            'status': self.status,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'profile_picture': self.profile_picture
        }

    @property
    def is_timed_out(self):
        return self.timeout_until and self.timeout_until > datetime.now()

    @staticmethod
    def get(user_id):
        user_data = load_user_data(user_id)
        if user_data:
            return User(
                user_data['username'], 
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
                user_data.get('last_seen'),
                user_data.get('profile_picture')
            )
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# --- Group Chat Functions ---
def load_group_chats():
    """Load group chat data"""
    with file_lock:
        try:
            if not os.path.exists(app.config['GROUP_CHATS_FILE']):
                return {}
            with open(app.config['GROUP_CHATS_FILE'], 'r') as f:
                return json.load(f)
        except Exception as e:
            app.logger.error(f"Error loading group chats: {e}")
            return {}

def save_group_chats(group_chats):
    """Save group chat data"""
    with file_lock:
        try:
            temp_file = app.config['GROUP_CHATS_FILE'] + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(group_chats, f, indent=4)
            os.replace(temp_file, app.config['GROUP_CHATS_FILE'])
            return True
        except Exception as e:
            app.logger.error(f"Error saving group chats: {e}")
            return False

# --- Data Persistence Functions with Error Handling ---
def load_all_users_data():
    """Load user data with error handling and file locking"""
    with file_lock:
        try:
            if not os.path.exists(app.config['USER_DATA_FILE']):
                return {}
            
            if os.path.exists(app.config['USER_DATA_FILE']):
                backup_file = app.config['USER_DATA_FILE'] + '.backup'
                try:
                    with open(app.config['USER_DATA_FILE'], 'r') as src:
                        with open(backup_file, 'w') as dst:
                            dst.write(src.read())
                except Exception as e:
                    app.logger.warning(f"Could not create backup: {e}")
            
            with open(app.config['USER_DATA_FILE'], 'r') as f:
                data = json.load(f)
                return data
        except json.JSONDecodeError as e:
            app.logger.error(f"JSON decode error in {app.config['USER_DATA_FILE']}: {e}")
            backup_file = app.config['USER_DATA_FILE'] + '.backup'
            if os.path.exists(backup_file):
                try:
                    with open(backup_file, 'r') as f:
                        data = json.load(f)
                        app.logger.info("Loaded data from backup file")
                        return data
                except:
                    pass
            return {}
        except Exception as e:
            app.logger.error(f"Error loading user data: {e}")
            return {}

def save_all_users_data(all_users_data):
    """Save user data with error handling and atomic writes"""
    with file_lock:
        try:
            temp_file = app.config['USER_DATA_FILE'] + '.tmp'
            
            with open(temp_file, 'w') as f:
                json.dump(all_users_data, f, indent=4)
            
            if os.path.exists(app.config['USER_DATA_FILE']):
                backup_file = app.config['USER_DATA_FILE'] + '.backup'
                os.replace(app.config['USER_DATA_FILE'], backup_file)
            
            os.replace(temp_file, app.config['USER_DATA_FILE'])
            return True
        except Exception as e:
            app.logger.error(f"Error saving user data: {e}")
            backup_file = app.config['USER_DATA_FILE'] + '.backup'
            if os.path.exists(backup_file) and not os.path.exists(app.config['USER_DATA_FILE']):
                try:
                    os.replace(backup_file, app.config['USER_DATA_FILE'])
                    app.logger.info("Restored from backup after save failure")
                except:
                    pass
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
                        data.get('last_seen'),
                        data.get('profile_picture'))
    return None

def add_message_to_history(room, message_data):
    """Add message with better error handling"""
    try:
        all_users = load_all_users_data()
        
        # Handle group chats
        if room.startswith('group_'):
            group_chats = load_group_chats()
            if room in group_chats:
                if 'messages' not in group_chats[room]:
                    group_chats[room]['messages'] = []
                group_chats[room]['messages'].append(message_data)
                # Limit to last 5000 messages
                if len(group_chats[room]['messages']) > 5000:
                    group_chats[room]['messages'] = group_chats[room]['messages'][-2500:]
                return save_group_chats(group_chats)
            return False
        
        # Handle direct messages
        user1, user2 = room.split('-')
        modified = False
        for user_key in [user1, user2]:
            if user_key in all_users:
                if 'chat_history' not in all_users[user_key]:
                    all_users[user_key]['chat_history'] = {}
                if room not in all_users[user_key]['chat_history']:
                    all_users[user_key]['chat_history'][room] = []
                
                if len(all_users[user_key]['chat_history'][room]) >= 5000:
                    all_users[user_key]['chat_history'][room] = all_users[user_key]['chat_history'][room][-2500:]
                
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
        # Handle group chats
        if room.startswith('group_'):
            group_chats = load_group_chats()
            if room in group_chats and 'messages' in group_chats[room]:
                for msg in group_chats[room]['messages']:
                    if msg.get('id') == message_id:
                        msg['msg'] = new_text
                        break
                return save_group_chats(group_chats)
            return False
        
        # Handle direct messages
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
        # Handle group chats
        if room.startswith('group_'):
            group_chats = load_group_chats()
            if room in group_chats and 'messages' in group_chats[room]:
                for msg in group_chats[room]['messages']:
                    if msg.get('id') == message_id:
                        msg['msg'] = "<em>deleted message</em>"
                        break
                return save_group_chats(group_chats)
            return False
        
        # Handle direct messages
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

def get_room_history(room_name, offset=0, limit=MESSAGES_PER_PAGE):
    """Get paginated room history"""
    try:
        # Handle group chats
        if room_name.startswith('group_'):
            group_chats = load_group_chats()
            if room_name in group_chats and 'messages' in group_chats[room_name]:
                messages = group_chats[room_name]['messages']
                total = len(messages)
                start = max(0, total - offset - limit)
                end = total - offset if offset > 0 else total
                return messages[start:end], total
            return [], 0
        
        # Handle direct messages
        user_data = load_user_data(current_user.username)
        if user_data and 'chat_history' in user_data and room_name in user_data['chat_history']:
            messages = user_data['chat_history'][room_name]
            total = len(messages)
            start = max(0, total - offset - limit)
            end = total - offset if offset > 0 else total
            return messages[start:end], total
        return [], 0
    except Exception as e:
        app.logger.error(f"Error getting room history: {e}")
        return [], 0

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
                'last_seen': data.get('last_seen'),
                'profile_picture': data.get('profile_picture')
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
            'settings': {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'},
            'timeout_until': None,
            'status': 'offline',
            'last_seen': datetime.now().isoformat(),
            'profile_picture': None
        }
        all_users[username] = new_user_data
        if save_all_users_data(all_users):
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed. Please try again.', 'error')
            return render_template('register.html', error='Registration failed.')

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
        
        if is_email_banned(user.email):
            flash('Your account is banned.', 'error')
            logout_user()
            return render_template('login.html', error='Your account is banned.')

        if user.is_timed_out:
            flash(f'Your account is temporarily timed out until {user.timeout_until.strftime("%Y-%m-%d %H:%M")}.', 'warning')
            return render_template('login.html', error='Account timed out.')

        login_user(user)
        update_user_status(user.username, 'online')
        flash('Logged in successfully!', 'success')
        return redirect(url_for('chat'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    update_user_status(current_user.username, 'offline')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    if current_user.is_timed_out:
        flash(f'Your account is temporarily timed out until {current_user.timeout_until.strftime("%Y-%m-%d %H:%M")}.', 'warning')
        logout_user()
        return redirect(url_for('login'))

    user_data = load_user_data(current_user.username)
    friends_list = user_data.get('friends', []) if user_data else []
    
    # Get group chats where user is a member
    group_chats = load_group_chats()
    user_groups = []
    for group_id, group_data in group_chats.items():
        if current_user.username in group_data.get('members', []):
            user_groups.append({
                'id': group_id,
                'name': group_data.get('name', 'Unnamed Group'),
                'members': group_data.get('members', [])
            })
    
    if user_data:
        session['primary_color'] = user_data['settings'].get('primary_color', '#0f0f0f')
        session['accent_color'] = user_data['settings'].get('accent_color', '#ff3f81')

    return render_template('chat.html', 
                           username=current_user.username, 
                           friends_list=friends_list,
                           group_chats=user_groups,
                           current_user=current_user)

@app.route('/history/<room_name>')
@login_required
def history(room_name):
    try:
        offset = int(request.args.get('offset', 0))
        limit = int(request.args.get('limit', MESSAGES_PER_PAGE))
        
        # Handle group chats
        if room_name.startswith('group_'):
            group_chats = load_group_chats()
            if room_name not in group_chats:
                return jsonify({'error': 'Group not found'}), 404
            
            if current_user.username not in group_chats[room_name].get('members', []):
                return jsonify({'error': 'You are not a member of this group'}), 403
            
            messages, total = get_room_history(room_name, offset, limit)
            return jsonify(messages=messages, total=total, has_more=(offset + len(messages)) < total)
        
        # Handle direct messages
        user1, user2 = room_name.split('-')
        
        if not (current_user.username == user1 or current_user.username == user2):
            return jsonify({'error': 'Unauthorized to view this chat history'}), 403

        current_user_data = load_user_data(current_user.username)
        if not current_user_data:
            return jsonify({'error': 'User data not found'}), 404
            
        target_username = user2 if current_user.username == user1 else user1

        if target_username not in current_user_data.get('friends', []):
            target_user_data = load_user_data(target_username)
            if target_user_data and current_user.username in target_user_data.get('blocked', []):
                return jsonify({'error': f'You are blocked by {target_username}. Cannot view chat history.'}), 403
            return jsonify({'error': 'You are not friends with this user. Cannot view chat history.'}), 403

        messages, total = get_room_history(room_name, offset, limit)
        return jsonify(messages=messages, total=total, has_more=(offset + len(messages)) < total)
    except Exception as e:
        app.logger.error(f"Error loading history: {e}")
        return jsonify({'error': 'Failed to load history'}), 500

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/profile_pics/<filename>')
def profile_picture(filename):
    return send_from_directory(app.config['PROFILE_PICS_FOLDER'], filename)

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    try:
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
            file.save(file_path)
            file_url = url_for('uploaded_file', filename=unique_filename)
            return jsonify({'url': file_url})
    except Exception as e:
        app.logger.error(f"Error saving file: {e}")
        return jsonify({'error': f'Failed to save file: {str(e)}'}), 500

@app.route('/upload_profile_picture', methods=['POST'])
@login_required
def upload_profile_picture():
    try:
        # Handle profile picture removal
        if request.is_json:
            data = request.get_json()
            if data.get('remove'):
                user_data = load_user_data(current_user.username)
                if user_data and user_data.get('profile_picture'):
                    old_pic = user_data['profile_picture'].split('/')[-1]
                    old_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], old_pic)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                    user_data['profile_picture'] = None
                    save_user_data(user_data)
                    return jsonify({'success': True})
                return jsonify({'error': 'No profile picture to remove'}), 400
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        # Check if file is an image
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
        if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
            return jsonify({'error': 'Invalid file type. Only images allowed.'}), 400
        
        filename = secure_filename(file.filename)
        timestamp = int(time.time())
        unique_filename = f"{current_user.username}_{timestamp}_{filename}"
        file_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], unique_filename)
        
        # Delete old profile picture if exists
        user_data = load_user_data(current_user.username)
        if user_data and user_data.get('profile_picture'):
            old_pic = user_data['profile_picture'].split('/')[-1]
            old_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], old_pic)
            if os.path.exists(old_path):
                os.remove(old_path)
        
        file.save(file_path)
        file_url = url_for('profile_picture', filename=unique_filename)
        
        # Update user data
        user_data['profile_picture'] = file_url
        save_user_data(user_data)
        
        return jsonify({'url': file_url})
    except Exception as e:
        app.logger.error(f"Error uploading profile picture: {e}")
        return jsonify({'error': f'Failed to upload profile picture: {str(e)}'}), 500

@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    try:
        data = request.get_json()
        group_name = data.get('name', '').strip()
        member_usernames = data.get('members', [])
        
        if not group_name:
            return jsonify({'error': 'Group name is required'}), 400
        
        if len(member_usernames) < 2:
            return jsonify({'error': 'At least 2 other members required'}), 400
        
        # Verify all members are friends
        user_data = load_user_data(current_user.username)
        for member in member_usernames:
            if member not in user_data.get('friends', []):
                return jsonify({'error': f'{member} is not your friend'}), 400
        
        # Create group
        group_id = f"group_{int(time.time())}_{secrets.token_hex(4)}"
        group_chats = load_group_chats()
        
        group_chats[group_id] = {
            'name': group_name,
            'creator': current_user.username,
            'members': [current_user.username] + member_usernames,
            'created_at': datetime.now().isoformat(),
            'messages': []
        }
        
        if save_group_chats(group_chats):
            return jsonify({'success': True, 'group_id': group_id, 'group_name': group_name})
        return jsonify({'error': 'Failed to create group'}), 500
    except Exception as e:
        app.logger.error(f"Error creating group: {e}")
        return jsonify({'error': 'Failed to create group'}), 500

@app.route('/get_group_info/<group_id>', methods=['GET'])
@login_required
def get_group_info(group_id):
    try:
        group_chats = load_group_chats()
        if group_id not in group_chats:
            return jsonify({'error': 'Group not found'}), 404
        
        group = group_chats[group_id]
        if current_user.username not in group.get('members', []):
            return jsonify({'error': 'You are not a member of this group'}), 403
        
        # Get profile pictures for members
        all_users = load_all_users_data()
        members_info = []
        for member in group.get('members', []):
            if member in all_users:
                members_info.append({
                    'username': member,
                    'profile_picture': all_users[member].get('profile_picture')
                })
        
        return jsonify({
            'name': group.get('name'),
            'creator': group.get('creator'),
            'members': members_info,
            'is_creator': current_user.username == group.get('creator')
        })
    except Exception as e:
        app.logger.error(f"Error getting group info: {e}")
        return jsonify({'error': 'Failed to get group info'}), 500

@app.route('/update_group/<group_id>', methods=['POST'])
@login_required
def update_group(group_id):
    try:
        data = request.get_json()
        action = data.get('action')
        
        group_chats = load_group_chats()
        if group_id not in group_chats:
            return jsonify({'error': 'Group not found'}), 404
        
        group = group_chats[group_id]
        
        if current_user.username not in group.get('members', []):
            return jsonify({'error': 'You are not a member of this group'}), 403
        
        if action == 'rename':
            if current_user.username != group.get('creator'):
                return jsonify({'error': 'Only the group creator can rename the group'}), 403
            
            new_name = data.get('name', '').strip()
            if not new_name:
                return jsonify({'error': 'Group name is required'}), 400
            
            group['name'] = new_name
            if save_group_chats(group_chats):
                return jsonify({'success': True, 'name': new_name})
            return jsonify({'error': 'Failed to rename group'}), 500
        
        elif action == 'kick':
            if current_user.username != group.get('creator'):
                return jsonify({'error': 'Only the group creator can kick members'}), 403
            
            member_to_kick = data.get('member')
            if not member_to_kick:
                return jsonify({'error': 'Member username is required'}), 400
            
            if member_to_kick == group.get('creator'):
                return jsonify({'error': 'Cannot kick the group creator'}), 400
            
            if member_to_kick in group['members']:
                group['members'].remove(member_to_kick)
                if save_group_chats(group_chats):
                    return jsonify({'success': True})
                return jsonify({'error': 'Failed to kick member'}), 500
            return jsonify({'error': 'Member not in group'}), 400
        
        elif action == 'leave':
            if current_user.username == group.get('creator'):
                return jsonify({'error': 'Group creator cannot leave. Delete the group instead.'}), 403
            
            if current_user.username in group['members']:
                group['members'].remove(current_user.username)
                if save_group_chats(group_chats):
                    return jsonify({'success': True})
                return jsonify({'error': 'Failed to leave group'}), 500
            return jsonify({'error': 'You are not in this group'}), 400
        
        return jsonify({'error': 'Invalid action'}), 400
    except Exception as e:
        app.logger.error(f"Error updating group: {e}")
        return jsonify({'error': 'Failed to update group'}), 500

@app.route('/get_user_profiles', methods=['POST'])
@login_required
def get_user_profiles():
    try:
        data = request.get_json()
        usernames = data.get('usernames', [])
        
        all_users = load_all_users_data()
        profiles = {}
        
        for username in usernames:
            if username in all_users:
                profiles[username] = {
                    'profile_picture': all_users[username].get('profile_picture')
                }
        
        return jsonify(profiles)
    except Exception as e:
        app.logger.error(f"Error getting user profiles: {e}")
        return jsonify({'error': 'Failed to get profiles'}), 500

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
                            if save_user_data(target_user_data):
                                message = f"Friend request sent to '{target_username}'."
                                message_type = "success"
                            else:
                                message = "Failed to send request. Please try again."
                                message_type = "error"

                    elif action == 'accept_request':
                        if target_username in user_data['requests']:
                            user_data['friends'].append(target_username)
                            user_data['requests'].remove(target_username)
                            
                            if username not in target_user_data['friends']:
                                target_user_data['friends'].append(username)
                            
                            if save_user_data(user_data) and save_user_data(target_user_data):
                                message = f"Accepted friend request from '{target_username}'."
                                message_type = "success"
                            else:
                                message = "Failed to accept request. Please try again."
                                message_type = "error"
                        else:
                            message = f"No pending request from '{target_username}'."
                            message_type = "error"

                    elif action == 'decline_request':
                        if target_username in user_data['requests']:
                            user_data['requests'].remove(target_username)
                            if save_user_data(user_data):
                                message = f"Declined friend request from '{target_username}'."
                                message_type = "success"
                            else:
                                message = "Failed to decline request."
                                message_type = "error"
                        else:
                            message = f"No pending request from '{target_username}'."
                            message_type = "error"

                    elif action == 'remove_friend':
                        if target_username in user_data['friends']:
                            user_data['friends'].remove(target_username)
                            if username in target_user_data['friends']:
                                target_user_data['friends'].remove(username)
                            if save_user_data(user_data) and save_user_data(target_user_data):
                                message = f"Removed '{target_username}' from friends."
                                message_type = "success"
                            else:
                                message = "Failed to remove friend."
                                message_type = "error"
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

                            if save_user_data(user_data) and save_user_data(target_user_data):
                                message = f"Blocked '{target_username}'."
                                message_type = "success"
                            else:
                                message = "Failed to block user."
                                message_type = "error"
                        else:
                            message = f"'{target_username}' is already blocked."
                            message_type = "error"

                    elif action == 'unblock_user':
                        if target_username in user_data['blocked']:
                            user_data['blocked'].remove(target_username)
                            if save_user_data(user_data):
                                message = f"Unblocked '{target_username}'."
                                message_type = "success"
                            else:
                                message = "Failed to unblock user."
                                message_type = "error"
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

    user_data = load_user_data(username)
    return render_template('friends.html', 
                           current_user=current_user, 
                           user_data=user_data, 
                           message=message, 
                           message_type=message_type)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_data = load_user_data(current_user.username)
    current_settings = user_data.get('settings', {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'}) if user_data else {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'}
    message = None
    message_type = None

    if request.method == 'POST':
        section = request.form.get('section', 'theme')
        
        if section == 'theme':
            new_primary = request.form.get('primary_color')
            new_accent = request.form.get('accent_color')

            if new_primary and new_accent:
                user_data['settings']['primary_color'] = new_primary
                user_data['settings']['accent_color'] = new_accent
                if save_user_data(user_data):
                    session['primary_color'] = new_primary
                    session['accent_color'] = new_accent
                    message = "Theme settings updated successfully!"
                    message_type = "success"
                else:
                    message = "Failed to update settings. Please try again."
                    message_type = "error"
            else:
                message = "Both colors are required."
                message_type = "error"
        
        elif section == 'account':
            new_username = request.form.get('username', '').strip()
            new_email = request.form.get('email', '').strip()
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            
            all_users = load_all_users_data()
            
            # Change username
            if new_username and new_username != current_user.username:
                if len(new_username) < 3:
                    message = "Username must be at least 3 characters."
                    message_type = "error"
                elif new_username in all_users:
                    message = "Username already taken."
                    message_type = "error"
                else:
                    # Update username everywhere
                    old_username = current_user.username
                    user_data['username'] = new_username
                    
                    # Update in all users' friend lists
                    for uname, udata in all_users.items():
                        if old_username in udata.get('friends', []):
                            udata['friends'].remove(old_username)
                            udata['friends'].append(new_username)
                        if old_username in udata.get('requests', []):
                            udata['requests'].remove(old_username)
                            udata['requests'].append(new_username)
                        if old_username in udata.get('blocked', []):
                            udata['blocked'].remove(old_username)
                            udata['blocked'].append(new_username)
                    
                    # Move user data to new key
                    all_users[new_username] = user_data
                    del all_users[old_username]
                    
                    if save_all_users_data(all_users):
                        logout_user()
                        flash('Username changed successfully! Please log in again.', 'success')
                        return redirect(url_for('login'))
                    else:
                        message = "Failed to change username."
                        message_type = "error"
            
            # Change email
            if new_email and new_email != user_data['email']:
                if not "@" in new_email or "." not in new_email:
                    message = "Invalid email format."
                    message_type = "error"
                else:
                    email_exists = False
                    for udata in all_users.values():
                        if udata['email'] == new_email:
                            email_exists = True
                            break
                    
                    if email_exists:
                        message = "Email already in use."
                        message_type = "error"
                    else:
                        user_data['email'] = new_email
                        if save_user_data(user_data):
                            message = "Email updated successfully!"
                            message_type = "success"
                        else:
                            message = "Failed to update email."
                            message_type = "error"
            
            # Change password
            if current_password and new_password:
                if not check_password_hash(user_data['password'], current_password):
                    message = "Current password is incorrect."
                    message_type = "error"
                elif len(new_password) < 6:
                    message = "New password must be at least 6 characters."
                    message_type = "error"
                else:
                    user_data['password'] = generate_password_hash(new_password)
                    if save_user_data(user_data):
                        message = "Password changed successfully!"
                        message_type = "success"
                    else:
                        message = "Failed to change password."
                        message_type = "error"

    current_settings = load_user_data(current_user.username).get('settings', {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'})
    user_data = load_user_data(current_user.username)
    return render_template('settings.html', 
                           current_user=current_user, 
                           settings=current_settings,
                           user_data=user_data,
                           message=message,
                           message_type=message_type)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_page():
    if current_user.username != 'admin':
        abort(403)

    all_users_data = load_all_users_data()
    banned_emails = load_banned_emails()
    
    users_for_template = []
    for username, data in all_users_data.items():
        if username != 'admin':
            users_for_template.append(User(username, username, data['email'], 
                                           data['password'], data.get('friends'), 
                                           data.get('requests'), data.get('blocked'), 
                                           data.get('chat_history'), data.get('settings'), 
                                           data.get('timeout_until'),
                                           data.get('status', 'offline'),
                                           data.get('last_seen'),
                                           data.get('profile_picture')))

    message = None
    message_type = None

    if request.method == 'POST':
        action = request.form.get('action')
        target_username = request.form.get('target_username')
        target_email = request.form.get('target_email')

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
                            message = f"User '{target_username}' deleted."
                            message_type = "success"
                        else:
                            message = "Failed to delete user."
                            message_type = "error"
                    
                    elif action == 'change_password':
                        new_password = request.form.get('new_password')
                        if not new_password or len(new_password) < 6:
                            message = "New password must be at least 6 characters."
                            message_type = "error"
                        else:
                            all_users_data[target_username]['password'] = generate_password_hash(new_password)
                            if save_all_users_data(all_users_data):
                                message = f"Password for '{target_username}' changed successfully."
                                message_type = "success"
                            else:
                                message = "Failed to change password."
                                message_type = "error"
                    
                    elif action == 'timeout':
                        minutes = int(request.form.get('minutes', 0))
                        if minutes > 0:
                            timeout_time = datetime.now() + timedelta(minutes=minutes)
                            all_users_data[target_username]['timeout_until'] = timeout_time.isoformat()
                            if save_all_users_data(all_users_data):
                                message = f"User '{target_username}' timed out for {minutes} minutes."
                                message_type = "success"
                            else:
                                message = "Failed to timeout user."
                                message_type = "error"
                        else:
                            message = "Invalid timeout duration."
                            message_type = "error"

                    elif action == 'untimeout':
                        all_users_data[target_username]['timeout_until'] = None
                        if save_all_users_data(all_users_data):
                            message = f"User '{target_username}' un-timed out."
                            message_type = "success"
                        else:
                            message = "Failed to untimeout user."
                            message_type = "error"

                    elif action == 'ban_user':
                        user_to_ban = all_users_data.get(target_username)
                        if user_to_ban and user_to_ban['email'] not in banned_emails:
                            banned_emails.append(user_to_ban['email'])
                            if save_banned_emails(banned_emails):
                                message = f"User '{target_username}' (email: {user_to_ban['email']}) banned."
                                message_type = "success"
                            else:
                                message = "Failed to ban user."
                                message_type = "error"
                        else:
                            message = f"Email for '{target_username}' is already banned or user not found."
                            message_type = "error"

                except Exception as e:
                    message = f"An error occurred: {e}"
                    message_type = "error"
                    app.logger.error(f"Admin action error: {e}")

        elif action == 'unban_email':
            if target_email and target_email in banned_emails:
                banned_emails.remove(target_email)
                if save_banned_emails(banned_emails):
                    message = f"Email '{target_email}' unbanned."
                    message_type = "success"
                else:
                    message = "Failed to unban email."
                    message_type = "error"
            else:
                message = f"Email '{target_email}' not found in banned list."
                message_type = "error"
        else:
            message = "Invalid admin action."
            message_type = "error"
    
    all_users_data = load_all_users_data()
    banned_emails = load_banned_emails()
    users_for_template = []
    for username, data in all_users_data.items():
        if username != 'admin':
            users_for_template.append(User(username, username, data['email'], 
                                           data['password'], data.get('friends'), 
                                           data.get('requests'), data.get('blocked'), 
                                           data.get('chat_history'), data.get('settings'), 
                                           data.get('timeout_until'),
                                           data.get('status', 'offline'),
                                           data.get('last_seen'),
                                           data.get('profile_picture')))

    return render_template('admin.html', 
                           current_user=current_user, 
                           users=users_for_template,
                           banned_list=banned_emails,
                           now=datetime.now(),
                           message=message, 
                           message_type=message_type,
                           show_login=False)

# === SOCKETIO EVENTS ===
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        username = current_user.username
        if username not in user_sids:
            user_sids[username] = []
        user_sids[username].append(request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        username = current_user.username
        if username in user_sids:
            if request.sid in user_sids[username]:
                user_sids[username].remove(request.sid)
            if not user_sids[username]:
                del user_sids[username]
                update_user_status(username, 'offline')
                
                user_data = load_user_data(username)
                if user_data:
                    for friend_username in user_data.get('friends', []):
                        if friend_username in user_sids:
                            for friend_sid in user_sids[friend_username]:
                                emit('user_status_update', {
                                    'username': username,
                                    'status': 'offline'
                                }, room=friend_sid)

@socketio.on('join')
def on_join(data):
    try:
        username = current_user.username
        room = data['room']
        
        if current_user.is_timed_out:
            emit('error', {'message': f'You are temporarily timed out until {current_user.timeout_until.strftime("%Y-%m-%d %H:%M")}.'}, room=request.sid)
            return

        # Handle group chats
        if room.startswith('group_'):
            group_chats = load_group_chats()
            if room not in group_chats:
                emit('error', {'message': 'Group not found.'}, room=request.sid)
                return
            
            if username not in group_chats[room].get('members', []):
                emit('error', {'message': 'You are not a member of this group.'}, room=request.sid)
                return
            
            join_room(room)
            app.logger.info(f'User {username} joined group: {room}')
            return

        # Handle direct messages
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
        
        if not user_data or not target_user_data:
            emit('error', {'message': 'User data not found.'}, room=request.sid)
            return

        if other_user not in user_data.get('friends', []):
            emit('error', {'message': f'You are not friends with {other_user}. Cannot join chat.'}, room=request.sid)
            return
        
        if username in target_user_data.get('blocked', []):
            emit('error', {'message': f'You are blocked by {other_user}. Cannot join chat.'}, room=request.sid)
            return

        join_room(room)
        app.logger.info(f'User {username} joined room: {room}')
        
        update_user_status(username, 'online')
        
        for friend_username in user_data.get('friends', []):
            if friend_username in user_sids:
                for friend_sid in user_sids[friend_username]:
                    emit('user_status_update', {
                        'username': username,
                        'status': 'online'
                    }, room=friend_sid)
    except Exception as e:
        app.logger.error(f"Error in on_join: {e}")
        emit('error', {'message': 'Failed to join room.'}, room=request.sid)

@socketio.on('leave')
def on_leave(data):
    try:
        username = current_user.username
        room = data['room']
        leave_room(room)
        app.logger.info(f'User {username} left room: {room}')
    except Exception as e:
        app.logger.error(f"Error in on_leave: {e}")

@socketio.on('send_message')
def handle_message(data):
    try:
        username = current_user.username
        room = data['room']
        msg = data['msg']
        reply_to = data.get('reply_to')
        
        if current_user.is_timed_out:
            emit('error', {'message': f'You are temporarily timed out until {current_user.timeout_until.strftime("%Y-%m-%d %H:%M")}. Cannot send messages.'}, room=request.sid)
            return
        
        if not check_rate_limit(username):
            emit('error', {'message': f'You are sending messages too quickly. Please wait a moment.'}, room=request.sid)
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
            emit('error', {'message': 'Failed to save message. Please try again.'}, room=request.sid)
            return

        app.logger.info(f'Message from {username} in {room}: {msg}')
        emit('message', message_data, room=room)
    except Exception as e:
        app.logger.error(f"Error in handle_message: {e}")
        emit('error', {'message': 'Failed to send message.'}, room=request.sid)

@socketio.on('edit_message')
def handle_edit_message(data):
    try:
        username = current_user.username
        message_id = data['message_id']
        new_text = data['new_text']
        room = data['room']

        if current_user.is_timed_out:
            emit('error', {'message': f'You are temporarily timed out until {current_user.timeout_until.strftime("%Y-%m-%d %H:%M")}. Cannot edit messages.'}, room=request.sid)
            return

        # Get message history
        if room.startswith('group_'):
            group_chats = load_group_chats()
            if room not in group_chats:
                emit('error', {'message': 'Group not found.'}, room=request.sid)
                return
            chat_history = group_chats[room].get('messages', [])
        else:
            user_data = load_user_data(username)
            if not user_data:
                emit('error', {'message': 'User data not found.'}, room=request.sid)
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
                    emit('error', {'message': 'Failed to update message.'}, room=request.sid)
                    return
                message_found = True
                break
        
        if message_found:
            emit('message_updated', {'id': message_id, 'new_text': updated_msg_content, 'room': room}, room=room)
            app.logger.info(f"User {username} edited message {message_id} in {room}.")
        else:
            emit('error', {'message': 'Message not found or you do not have permission to edit this message.'}, room=request.sid)
    except Exception as e:
        app.logger.error(f"Error in handle_edit_message: {e}")
        emit('error', {'message': 'Failed to edit message.'}, room=request.sid)

@socketio.on('delete_message')
def handle_delete_message(data):
    try:
        username = current_user.username
        message_id = data['message_id']
        room = data['room']

        if current_user.is_timed_out:
            emit('error', {'message': f'You are temporarily timed out until {current_user.timeout_until.strftime("%Y-%m-%d %H:%M")}. Cannot delete messages.'}, room=request.sid)
            return

        # Get message history
        if room.startswith('group_'):
            group_chats = load_group_chats()
            if room not in group_chats:
                emit('error', {'message': 'Group not found.'}, room=request.sid)
                return
            chat_history = group_chats[room].get('messages', [])
        else:
            user_data = load_user_data(username)
            if not user_data:
                emit('error', {'message': 'User data not found.'}, room=request.sid)
                return
            chat_history = user_data.get('chat_history', {}).get(room, [])

        message_found = False
        for msg_obj in chat_history:
            if msg_obj.get('id') == message_id and msg_obj.get('username') == username:
                if not delete_message_from_history(room, message_id):
                    emit('error', {'message': 'Failed to delete message.'}, room=request.sid)
                    return
                message_found = True
                break
        
        if message_found:
            emit('message_updated', {'id': message_id, 'new_text': "<em>deleted message</em>", 'room': room}, room=room)
            app.logger.info(f"User {username} deleted message {message_id} in {room}.")
        else:
            emit('error', {'message': 'Message not found or you do not have permission to delete this message.'}, room=request.sid)
    except Exception as e:
        app.logger.error(f"Error in handle_delete_message: {e}")
        emit('error', {'message': 'Failed to delete message.'}, room=request.sid)

@socketio.on('user_connected')
def handle_user_connected():
    try:
        username = current_user.username
        if current_user.is_timed_out:
            emit('error', {'message': f'You are temporarily timed out until {current_user.timeout_until.strftime("%Y-%m-%d %H:%M")}.'}, room=request.sid)
            return
        
        update_user_status(username, 'online')
        
        user_data = load_user_data(username)
        if user_data:
            for friend_username in user_data.get('friends', []):
                if friend_username in user_sids:
                    for friend_sid in user_sids[friend_username]:
                        emit('user_status_update', {
                            'username': username,
                            'status': 'online'
                        }, room=friend_sid)
    except Exception as e:
        app.logger.error(f"Error in handle_user_connected: {e}")

@socketio.on('user_disconnected')
def handle_user_disconnected():
    try:
        username = current_user.username
        update_user_status(username, 'offline')
        
        user_data = load_user_data(username)
        if user_data:
            for friend_username in user_data.get('friends', []):
                if friend_username in user_sids:
                    for friend_sid in user_sids[friend_username]:
                        emit('user_status_update', {
                            'username': username,
                            'status': 'offline'
                        }, room=friend_sid)
    except Exception as e:
        app.logger.error(f"Error in handle_user_disconnected: {e}")

@socketio.on('typing_start')
def handle_typing_start(data):
    try:
        room = data['room']
        username = current_user.username
        
        if current_user.is_timed_out:
            return
        
        emit('user_typing', {
            'username': username,
            'is_typing': True
        }, room=room, include_self=False)
    except Exception as e:
        app.logger.error(f"Error in handle_typing_start: {e}")

@socketio.on('typing_stop')
def handle_typing_stop(data):
    try:
        room = data['room']
        username = current_user.username
        
        if current_user.is_timed_out:
            return
        
        emit('user_typing', {
            'username': username,
            'is_typing': False
        }, room=room, include_self=False)
    except Exception as e:
        app.logger.error(f"Error in handle_typing_stop: {e}")

@socketio.on('request_statuses')
def handle_request_statuses():
    try:
        all_statuses = get_all_users_statuses()
        user_data = load_user_data(current_user.username)
        if user_data:
            friends = user_data.get('friends', [])
            friend_statuses = {k: v for k, v in all_statuses.items() if k in friends}
            emit('all_statuses', friend_statuses)
    except Exception as e:
        app.logger.error(f"Error in handle_request_statuses: {e}")

# --- Video/Audio Call Events ---
@socketio.on('call_user')
def handle_call_user(data):
    try:
        caller = current_user.username
        receiver = data['receiver']
        call_type = data['type']
        room = data['room']
        
        if current_user.is_timed_out:
            emit('error', {'message': 'You are timed out and cannot make calls.'}, room=request.sid)
            return
        
        user_data = load_user_data(caller)
        if not user_data or receiver not in user_data.get('friends', []):
            emit('error', {'message': 'You can only call friends.'}, room=request.sid)
            return
        
        if receiver not in user_sids:
            emit('error', {'message': f'{receiver} is not online.'}, room=request.sid)
            return
        
        if room in active_calls:
            emit('error', {'message': 'There is already an active call.'}, room=request.sid)
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
        emit('error', {'message': 'Failed to initiate call.'}, room=request.sid)

@socketio.on('answer_call')
def handle_answer_call(data):
    try:
        answerer = current_user.username
        caller = data['caller']
        room = data['room']
        call_type = data['type']
        
        active_calls[room] = {
            'caller': caller,
            'receiver': answerer,
            'type': call_type
        }
        
        if caller in user_sids:
            for caller_sid in user_sids[caller]:
                emit('call_answered', {
                    'answerer': answerer,
                    'room': room
                }, room=caller_sid)
        
        app.logger.info(f'{answerer} answered call from {caller}')
    except Exception as e:
        app.logger.error(f"Error in handle_answer_call: {e}")

@socketio.on('reject_call')
def handle_reject_call(data):
    try:
        rejecter = current_user.username
        caller = data['caller']
        room = data['room']
        
        if caller in user_sids:
            for caller_sid in user_sids[caller]:
                emit('call_rejected', {
                    'rejecter': rejecter,
                    'room': room
                }, room=caller_sid)
        
        app.logger.info(f'{rejecter} rejected call from {caller}')
    except Exception as e:
        app.logger.error(f"Error in handle_reject_call: {e}")

@socketio.on('end_call')
def handle_end_call(data):
    try:
        username = current_user.username
        room = data['room']
        
        if room in active_calls:
            call_info = active_calls[room]
            del active_calls[room]
            
            other_user = call_info['caller'] if call_info['receiver'] == username else call_info['receiver']
            if other_user in user_sids:
                for other_sid in user_sids[other_user]:
                    emit('call_ended', {
                        'room': room,
                        'ended_by': username
                    }, room=other_sid)
        
        app.logger.info(f'{username} ended call in room {room}')
    except Exception as e:
        app.logger.error(f"Error in handle_end_call: {e}")

@socketio.on('webrtc_offer')
def handle_webrtc_offer(data):
    try:
        sender = current_user.username
        room = data['room']
        offer = data['offer']
        
        emit('webrtc_offer', {
            'offer': offer,
            'sender': sender
        }, room=room, include_self=False)
    except Exception as e:
        app.logger.error(f"Error in handle_webrtc_offer: {e}")

@socketio.on('webrtc_answer')
def handle_webrtc_answer(data):
    try:
        sender = current_user.username
        room = data['room']
        answer = data['answer']
        
        emit('webrtc_answer', {
            'answer': answer,
            'sender': sender
        }, room=room, include_self=False)
    except Exception as e:
        app.logger.error(f"Error in handle_webrtc_answer: {e}")

@socketio.on('webrtc_ice_candidate')
def handle_ice_candidate(data):
    try:
        sender = current_user.username
        room = data['room']
        candidate = data['candidate']
        
        emit('webrtc_ice_candidate', {
            'candidate': candidate,
            'sender': sender
        }, room=room, include_self=False)
    except Exception as e:
        app.logger.error(f"Error in handle_ice_candidate: {e}")

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
            'last_seen': datetime.now().isoformat(),
            'profile_picture': None
        }
        all_users['admin'] = admin_data
        save_all_users_data(all_users)
        print("Admin user created with username 'admin' and password 'admin'")
        print("!!! IMPORTANT: Change admin password immediately in app.py for production !!!")

    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, host="0.0.0.0", port=5001)
