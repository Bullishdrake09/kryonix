import os
import json
import time
import re
import secrets
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message as MailMessage
from sqlalchemy import Text, JSON
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import logging
from collections import defaultdict, deque

# Configure logging
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

# ── Secret key & DB ──
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROFILE_PICS_FOLDER'] = 'profile_pics'
app.config['SOUNDS_FOLDER'] = 'custom_sounds'
app.config['CUSTOM_CSS_FOLDER'] = 'custom_css'          # ← NEW
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# ── Flask-Mail (Email 2FA) ──
app.config['MAIL_SERVER']   = os.environ.get('MAIL_SERVER',   'smtp.gmail.com')
app.config['MAIL_PORT']     = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS']  = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'thomas.desmidt1@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'qhoprwfspjhuciwu')
mail = Mail(app)

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'webm', 'ogg', 'mov'}
ALLOWED_UPLOAD_EXTENSIONS = ALLOWED_IMAGE_EXTENSIONS | ALLOWED_VIDEO_EXTENSIONS
ALLOWED_SOUND_EXTENSIONS  = {'mp3', 'ogg', 'wav'}
ALLOWED_THEMES            = {'kryonix', 'dark', 'light', 'custom'}
MAX_CUSTOM_CSS_BYTES      = 200 * 1024   # 200 KB

for folder in (
    app.config['UPLOAD_FOLDER'],
    app.config['PROFILE_PICS_FOLDER'],
    app.config['SOUNDS_FOLDER'],
    app.config['CUSTOM_CSS_FOLDER'],   # ← NEW
):
    if not os.path.exists(folder):
        os.makedirs(folder)

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

user_sids = {}
active_calls = {}
active_group_calls = {}

# Rate limiting
user_message_times = defaultdict(lambda: deque(maxlen=20))
RATE_LIMIT_MESSAGES = 10
RATE_LIMIT_WINDOW = 5
MESSAGES_PER_PAGE = 50
MAX_MESSAGE_LENGTH = 3000

# ─────────────────────────────────────────────
# DATABASE MODELS
# ─────────────────────────────────────────────

class UserModel(db.Model):
    __tablename__ = 'users'

    username        = db.Column(db.String(80),  primary_key=True)
    email           = db.Column(db.String(120), unique=True, nullable=False)
    password_hash   = db.Column(db.String(256), nullable=False)
    # Lists stored as JSON arrays
    friends         = db.Column(JSON, default=list)
    requests        = db.Column(JSON, default=list)
    blocked         = db.Column(JSON, default=list)
    settings        = db.Column(JSON, default=lambda: {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'})
    timeout_until   = db.Column(db.DateTime, nullable=True)
    status          = db.Column(db.String(20), default='offline')
    last_seen       = db.Column(db.DateTime, default=datetime.utcnow)
    profile_picture = db.Column(db.String(256), nullable=True)
    is_banned       = db.Column(db.Boolean, default=False)
    email_verified  = db.Column(db.Boolean, default=False)
    sound_message   = db.Column(db.String(256), nullable=True)
    sound_calling   = db.Column(db.String(256), nullable=True)
    # ── Appearance / theme ──────────────────────────────────────────────────
    active_theme    = db.Column(db.String(20),  default='kryonix', nullable=False)
    custom_css_url  = db.Column(db.String(256), nullable=True)

    # Relationships
    sent_messages   = db.relationship('Message',      back_populates='author',     lazy='dynamic',
                                       foreign_keys='Message.sender_username')
    group_memberships = db.relationship('GroupMember', back_populates='user',       lazy='dynamic')


class BannedEmail(db.Model):
    __tablename__ = 'banned_emails'

    id    = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)


class Message(db.Model):
    __tablename__ = 'messages'

    id               = db.Column(db.String(64),  primary_key=True)
    room             = db.Column(db.String(200),  nullable=False, index=True)
    sender_username  = db.Column(db.String(80),  db.ForeignKey('users.username'), nullable=False)
    content          = db.Column(db.Text,  nullable=False)
    timestamp        = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    time_display     = db.Column(db.String(10))
    is_deleted       = db.Column(db.Boolean, default=False)
    reply_to         = db.Column(JSON, nullable=True)

    author = db.relationship('UserModel', back_populates='sent_messages',
                             foreign_keys=[sender_username])


class GroupChat(db.Model):
    __tablename__ = 'group_chats'

    id         = db.Column(db.String(64),  primary_key=True)
    name       = db.Column(db.String(100), nullable=False)
    creator    = db.Column(db.String(80),  db.ForeignKey('users.username'), nullable=False)
    created_at = db.Column(db.DateTime,    default=datetime.utcnow)

    members  = db.relationship('GroupMember', back_populates='group', lazy='dynamic',
                                cascade='all, delete-orphan')


class GroupMember(db.Model):
    __tablename__ = 'group_members'

    group_id = db.Column(db.String(64), db.ForeignKey('group_chats.id'), primary_key=True)
    username = db.Column(db.String(80), db.ForeignKey('users.username'), primary_key=True)

    group = db.relationship('GroupChat',  back_populates='members')
    user  = db.relationship('UserModel',  back_populates='group_memberships')


# ─────────────────────────────────────────────
# FLASK-LOGIN USER CLASS
# ─────────────────────────────────────────────

class User(UserMixin):
    """Thin wrapper around UserModel for Flask-Login."""

    def __init__(self, model: UserModel):
        self._m = model

    def get_id(self):
        return self._m.username

    @property
    def id(self):           return self._m.username
    @property
    def username(self):     return self._m.username
    @property
    def email(self):        return self._m.email
    @property
    def password_hash(self):return self._m.password_hash
    @property
    def friends(self):      return self._m.friends or []
    @property
    def requests(self):     return self._m.requests or []
    @property
    def blocked(self):      return self._m.blocked or []
    @property
    def settings(self):     return self._m.settings or {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'}
    @property
    def timeout_until(self):return self._m.timeout_until
    @property
    def status(self):       return self._m.status
    @property
    def profile_picture(self): return self._m.profile_picture
    @property
    def sound_message(self):  return self._m.sound_message
    @property
    def sound_calling(self):  return self._m.sound_calling
    @property
    def active_theme(self):   return self._m.active_theme or 'kryonix'
    @property
    def custom_css_url(self):  return self._m.custom_css_url

    @property
    def is_timed_out(self):
        return self._m.timeout_until and self._m.timeout_until > datetime.utcnow()


@login_manager.user_loader
def load_user(username):
    m = UserModel.query.get(username)
    return User(m) if m else None


# ─────────────────────────────────────────────
# CSRF
# ─────────────────────────────────────────────

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def validate_csrf(token):
    return token and token == session.get('csrf_token')


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

def check_rate_limit(username):
    now = time.time()
    user_times = user_message_times[username]
    while user_times and user_times[0] < now - RATE_LIMIT_WINDOW:
        user_times.popleft()
    if len(user_times) >= RATE_LIMIT_MESSAGES:
        return False
    user_times.append(now)
    return True

_TAG_RE = re.compile(r'<[^>]+>')
def strip_tags(text):
    return _TAG_RE.sub('', text or '')


# ─────────────────────────────────────────────
# THEME SESSION HELPER
# ─────────────────────────────────────────────

def _load_theme_into_session(user_model: UserModel):
    """Push the user's saved theme into the Flask session so base.html can inject it.
    Must be called inside a request context so url_for() works.
    """
    theme = user_model.active_theme or 'kryonix'
    session['active_theme'] = theme

    if theme == 'custom':
        session['custom_css_url'] = user_model.custom_css_url or None
    elif theme == 'dark':
        session['custom_css_url'] = url_for('static', filename='css/theme-dark.css')
    elif theme == 'light':
        session['custom_css_url'] = url_for('static', filename='css/theme-light.css')
    else:
        # 'kryonix' or any unknown value → load the kryonix theme variables file
        session['custom_css_url'] = url_for('static', filename='css/theme-kryonix.css')


# ─────────────────────────────────────────────
# DB HELPER FUNCTIONS
# ─────────────────────────────────────────────

def get_user_model(username) -> UserModel | None:
    return UserModel.query.get(username)

def get_user_by_login(login_field) -> User | None:
    m = UserModel.query.filter(
        (UserModel.username == login_field) | (UserModel.email == login_field)
    ).first()
    return User(m) if m else None

def is_email_banned(email: str) -> bool:
    return BannedEmail.query.filter_by(email=email.lower()).first() is not None

def update_user_status(username: str, status: str):
    m = get_user_model(username)
    if m:
        m.status    = status
        m.last_seen = datetime.utcnow()
        db.session.commit()

def get_room_history(room_name: str, offset: int = 0, limit: int = MESSAGES_PER_PAGE):
    total = Message.query.filter_by(room=room_name).count()
    msgs  = (Message.query
             .filter_by(room=room_name)
             .order_by(Message.timestamp.asc())
             .offset(offset)
             .limit(limit)
             .all())
    result = []
    for m in msgs:
        d = {
            'id':       m.id,
            'username': m.sender_username,
            'msg':      m.content,
            'time':     m.time_display,
            'room':     m.room,
        }
        if m.reply_to:
            d['reply_to'] = m.reply_to
        result.append(d)
    return result, total

def add_message_to_db(room: str, message_data: dict) -> bool:
    try:
        msg = Message(
            id              = message_data['id'],
            room            = room,
            sender_username = message_data['username'],
            content         = message_data['msg'],
            time_display    = message_data.get('time', ''),
            reply_to        = message_data.get('reply_to'),
        )
        db.session.add(msg)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding message: {e}")
        return False

def update_message_in_db(message_id: str, new_text: str) -> bool:
    try:
        msg = Message.query.get(message_id)
        if msg:
            msg.content    = new_text
            msg.is_deleted = new_text == "<em>deleted message</em>"
            db.session.commit()
            return True
        return False
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating message: {e}")
        return False

def delete_message_in_db(message_id: str) -> bool:
    try:
        msg = Message.query.get(message_id)
        if msg:
            msg.content    = "<em>deleted message</em>"
            msg.is_deleted = True
            db.session.commit()
            return True
        return False
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting message: {e}")
        return False

def get_group_members(group_id: str) -> list[str]:
    return [gm.username for gm in GroupMember.query.filter_by(group_id=group_id).all()]

def user_in_group(username: str, group_id: str) -> bool:
    return GroupMember.query.filter_by(group_id=group_id, username=username).first() is not None


# ─────────────────────────────────────────────
# EMAIL 2FA HELPERS
# ─────────────────────────────────────────────

def generate_2fa_code():
    return str(random.randint(100000, 999999))

def send_2fa_email(recipient: str, code: str, subject: str = "Kryonix Verification Code"):
    try:
        msg = MailMessage(
            subject   = subject,
            sender    = app.config['MAIL_USERNAME'],
            recipients= [recipient],
        )
        msg.body = (
            f"Your Kryonix verification code is: {code}\n\n"
            "This code expires in 10 minutes.\n"
            "If you did not request this, please ignore this email."
        )
        is_login = "Login" in subject
        headline = "Login Verification" if is_login else "Verify Your Email"
        sub_line = (
            "Use the code below to complete your login."
            if is_login else
            "You're almost in! Use the code below to verify your email address."
        )
        msg.html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>{subject}</title>
</head>
<body style="margin:0;padding:0;background:#0d0d0d;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d0d0d;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="520" cellpadding="0" cellspacing="0"
               style="background:#181818;border-radius:16px;overflow:hidden;
                      border:1px solid #2a2a2a;max-width:520px;width:100%;">
          <tr>
            <td style="background:linear-gradient(135deg,#ff3f81,#c0226a);
                       padding:32px 40px;text-align:center;">
              <p style="margin:0;font-size:28px;font-weight:800;
                         color:#ffffff;letter-spacing:2px;text-transform:uppercase;">
                ✦ KRYONIX
              </p>
              <p style="margin:8px 0 0;font-size:13px;color:rgba(255,255,255,0.75);
                         letter-spacing:1px;text-transform:uppercase;">
                Secure Messaging
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding:40px 40px 20px;text-align:center;">
              <h1 style="margin:0 0 12px;font-size:22px;font-weight:700;color:#ffffff;">
                {headline}
              </h1>
              <p style="margin:0 0 32px;font-size:15px;color:#aaaaaa;line-height:1.6;">
                {sub_line}
              </p>
              <div style="background:#0d0d0d;border:1px solid #ff3f81;border-radius:12px;
                           display:inline-block;padding:20px 48px;margin-bottom:32px;">
                <p style="margin:0;font-size:11px;letter-spacing:2px;color:#ff3f81;
                            text-transform:uppercase;margin-bottom:8px;">Your code</p>
                <p style="margin:0;font-size:40px;font-weight:800;letter-spacing:10px;
                            color:#ffffff;font-family:'Courier New',monospace;">{code}</p>
              </div>
              <p style="margin:0 0 8px;font-size:13px;color:#666;">
                ⏱ This code expires in <strong style="color:#aaa;">10 minutes</strong>.
              </p>
              <p style="margin:0;font-size:13px;color:#555;">
                If you didn't request this, you can safely ignore this email.
              </p>
            </td>
          </tr>
          <tr><td style="padding:0 40px;"><div style="height:1px;background:#2a2a2a;"></div></td></tr>
          <tr>
            <td style="padding:20px 40px 32px;text-align:center;">
              <p style="margin:0;font-size:12px;color:#444;">
                © 2024 Kryonix. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"Failed to send email to {recipient}: {e}")

def _mask_email(email: str) -> str:
    if not email or '@' not in email:
        return email
    local, domain = email.split('@', 1)
    visible = local[:2] if len(local) >= 2 else local
    return f"{visible}***@{domain}"


# ─────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    """Root redirect — send logged-in users to chat, everyone else to login."""
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email    = (request.form.get('email') or '').strip().lower()
        password =  request.form.get('password') or ''

        if not username or not email or not password:
            return render_template('register.html', error='All fields are required.')
        if len(username) < 3:
            return render_template('register.html', error='Username must be at least 3 characters.')
        if not re.match(r'^[\w.-]+$', username):
            return render_template('register.html', error='Username may only contain letters, numbers, dots, dashes, and underscores.')
        if '@' not in email or '.' not in email.split('@')[-1]:
            return render_template('register.html', error='Invalid email format.')
        if len(password) < 6:
            return render_template('register.html', error='Password must be at least 6 characters.')
        if UserModel.query.get(username):
            return render_template('register.html', error='Username already taken.')
        if UserModel.query.filter_by(email=email).first():
            return render_template('register.html', error='Email already registered.')
        if is_email_banned(email):
            return render_template('register.html', error='This email address is banned from registration.')

        m = UserModel(
            username      = username,
            email         = email,
            password_hash = generate_password_hash(password),
            friends       = [],
            requests      = [],
            blocked       = [],
            settings      = {'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'},
            status        = 'offline',
            last_seen     = datetime.utcnow(),
            email_verified= False,
            active_theme  = 'kryonix',
        )
        db.session.add(m)
        db.session.commit()

        code = generate_2fa_code()
        session['verify_code']      = code
        session['verify_email']     = email
        session['verify_username']  = username
        session['verify_code_time'] = time.time()
        send_2fa_email(email, code, subject="Kryonix — Verify Your Email")
        return redirect(url_for('verify_email'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))

    if request.method == 'POST':
        login_field = (request.form.get('login_field') or '').strip()
        password    =  request.form.get('password') or ''

        user = get_user_by_login(login_field)
        if not user or not check_password_hash(user.password_hash, password):
            return render_template('login.html', error='Invalid username/email or password.')
        if is_email_banned(user.email):
            return render_template('login.html', error='Your account is banned.')
        if user.is_timed_out:
            return render_template('login.html', error=f'Account timed out until {user.timeout_until.strftime("%Y-%m-%d %H:%M")}.')

        m = get_user_model(user.username)
        if not m.email_verified:
            code = generate_2fa_code()
            session['verify_code']      = code
            session['verify_email']     = user.email
            session['verify_username']  = user.username
            session['verify_code_time'] = time.time()
            send_2fa_email(user.email, code, subject="Kryonix — Verify Your Email")
            return render_template('login.html', error='Email not verified. A new verification code has been sent to your email.')

        code = generate_2fa_code()
        session['login_2fa_code']     = code
        session['login_2fa_username'] = user.username
        session['login_2fa_time']     = time.time()
        send_2fa_email(user.email, code, subject="Kryonix — Login Verification Code")
        return redirect(url_for('verify_login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    update_user_status(current_user.username, 'offline')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ─────────────────────────────────────────────
# EMAIL VERIFICATION
# ─────────────────────────────────────────────

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    if 'verify_email' not in session:
        return redirect(url_for('register'))

    error = None
    if request.method == 'POST':
        entered = (request.form.get('code') or '').strip()
        stored  = session.get('verify_code')
        issued  = session.get('verify_code_time', 0)

        if time.time() - issued > 600:
            error = 'Code expired. Please register again.'
            for k in ('verify_code', 'verify_email', 'verify_username', 'verify_code_time'):
                session.pop(k, None)
        elif entered != stored:
            error = 'Incorrect code. Please try again.'
        else:
            username = session.pop('verify_username', None)
            for k in ('verify_code', 'verify_email', 'verify_code_time'):
                session.pop(k, None)
            m = get_user_model(username)
            if m:
                m.email_verified = True
                db.session.commit()
            return render_template('verify_email.html', verified=True)

    return render_template('verify_email.html', error=error, verified=False,
                           masked_email=_mask_email(session.get('verify_email', '')))


@app.route('/verify-email/resend')
def resend_verify_email():
    if 'verify_email' not in session:
        return redirect(url_for('register'))
    code = generate_2fa_code()
    session['verify_code']      = code
    session['verify_code_time'] = time.time()
    send_2fa_email(session['verify_email'], code, subject="Kryonix — Verify Your Email")
    flash('A new verification code has been sent.', 'info')
    return redirect(url_for('verify_email'))


# ─────────────────────────────────────────────
# LOGIN 2FA
# ─────────────────────────────────────────────

@app.route('/verify-login', methods=['GET', 'POST'])
def verify_login():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    if 'login_2fa_username' not in session:
        return redirect(url_for('login'))

    error = None
    if request.method == 'POST':
        entered = (request.form.get('code') or '').strip()
        stored  = session.get('login_2fa_code')
        issued  = session.get('login_2fa_time', 0)

        if time.time() - issued > 600:
            error = 'Code expired. Please log in again.'
            for k in ('login_2fa_code', 'login_2fa_username', 'login_2fa_time'):
                session.pop(k, None)
        elif entered != stored:
            error = 'Incorrect code. Please try again.'
        else:
            username = session.pop('login_2fa_username')
            for k in ('login_2fa_code', 'login_2fa_time'):
                session.pop(k, None)
            m = get_user_model(username)
            if not m:
                return redirect(url_for('login'))
            user = User(m)
            login_user(user)
            update_user_status(username, 'online')
            # ── Load theme into session immediately after login ──
            _load_theme_into_session(m)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('chat'))

    username = session.get('login_2fa_username', '')
    m = get_user_model(username)
    masked = _mask_email(m.email) if m else ''
    return render_template('verify_login.html', error=error, masked_email=masked)


@app.route('/verify-login/resend')
def resend_login_2fa():
    username = session.get('login_2fa_username')
    if not username:
        return redirect(url_for('login'))
    m = get_user_model(username)
    if not m:
        return redirect(url_for('login'))
    code = generate_2fa_code()
    session['login_2fa_code'] = code
    session['login_2fa_time'] = time.time()
    send_2fa_email(m.email, code, subject="Kryonix — Login Verification Code")
    flash('A new code has been sent to your email.', 'info')
    return redirect(url_for('verify_login'))


# ─────────────────────────────────────────────
# CHAT
# ─────────────────────────────────────────────

@app.route('/chat')
@login_required
def chat():
    if current_user.is_timed_out:
        flash(f'Your account is timed out until {current_user.timeout_until.strftime("%Y-%m-%d %H:%M")}.', 'warning')
        logout_user()
        return redirect(url_for('login'))

    m = get_user_model(current_user.username)
    friends_list = m.friends or []

    user_groups = []
    for gm in GroupMember.query.filter_by(username=current_user.username).all():
        g = gm.group
        user_groups.append({
            'id':      g.id,
            'name':    g.name,
            'members': get_group_members(g.id),
        })

    if m:
        session['primary_color'] = (m.settings or {}).get('primary_color', '#0f0f0f')
        session['accent_color']  = (m.settings or {}).get('accent_color',  '#ff3f81')
        # ── Always keep theme in sync with DB ──
        _load_theme_into_session(m)

    return render_template('chat.html',
                           username=current_user.username,
                           friends_list=friends_list,
                           group_chats=user_groups,
                           current_user=current_user,
                           max_message_length=MAX_MESSAGE_LENGTH)


@app.route('/history/<room_name>')
@login_required
def history(room_name):
    try:
        offset = int(request.args.get('offset', 0))
        limit  = min(int(request.args.get('limit', MESSAGES_PER_PAGE)), 100)

        if room_name.startswith('group_'):
            g = GroupChat.query.get(room_name)
            if not g:
                return jsonify({'error': 'Group not found'}), 404
            if not user_in_group(current_user.username, room_name):
                return jsonify({'error': 'You are not a member of this group'}), 403
            messages, total = get_room_history(room_name, offset, limit)
            return jsonify(messages=messages, total=total, has_more=(offset + len(messages)) < total)

        parts = room_name.split('-')
        if len(parts) != 2:
            return jsonify({'error': 'Invalid room name'}), 400
        user1, user2 = parts
        if current_user.username not in (user1, user2):
            return jsonify({'error': 'Unauthorized'}), 403

        m = get_user_model(current_user.username)
        target = user2 if current_user.username == user1 else user1
        if target not in (m.friends or []):
            return jsonify({'error': 'You are not friends with this user.'}), 403

        messages, total = get_room_history(room_name, offset, limit)
        return jsonify(messages=messages, total=total, has_more=(offset + len(messages)) < total)
    except Exception as e:
        app.logger.error(f"Error loading history: {e}")
        return jsonify({'error': 'Failed to load history'}), 500


# ─────────────────────────────────────────────
# FILE SERVING
# ─────────────────────────────────────────────

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    safe = secure_filename(filename)
    if safe != filename:
        abort(400)
    return send_from_directory(app.config['UPLOAD_FOLDER'], safe)


@app.route('/profile_pics/<filename>')
def profile_picture(filename):
    safe = secure_filename(filename)
    if safe != filename:
        abort(400)
    return send_from_directory(app.config['PROFILE_PICS_FOLDER'], safe)


@app.route('/custom_css/<filename>')
@login_required
def custom_css_file(filename):
    safe = secure_filename(filename)
    if safe != filename:
        abort(400)
    return send_from_directory(app.config['CUSTOM_CSS_FOLDER'], safe)



# ─────────────────────────────────────────────
# FILE UPLOAD
# ─────────────────────────────────────────────

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        if not allowed_file(file.filename, ALLOWED_UPLOAD_EXTENSIONS):
            return jsonify({'error': 'File type not allowed.'}), 400
        filename        = secure_filename(file.filename)
        unique_filename = f"{int(time.time())}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        return jsonify({'url': url_for('uploaded_file', filename=unique_filename)})
    except Exception as e:
        app.logger.error(f"Error saving file: {e}")
        return jsonify({'error': f'Failed to save file: {e}'}), 500


@app.route('/upload_profile_picture', methods=['POST'])
@login_required
def upload_profile_picture():
    try:
        m = get_user_model(current_user.username)

        if request.is_json:
            data = request.get_json()
            if data.get('remove'):
                if m and m.profile_picture:
                    old_pic  = m.profile_picture.split('/')[-1]
                    old_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], secure_filename(old_pic))
                    if os.path.exists(old_path):
                        os.remove(old_path)
                    m.profile_picture = None
                    db.session.commit()
                    return jsonify({'success': True})
                return jsonify({'error': 'No profile picture to remove'}), 400

        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        if not allowed_file(file.filename, ALLOWED_IMAGE_EXTENSIONS):
            return jsonify({'error': 'Invalid file type.'}), 400

        filename        = secure_filename(file.filename)
        unique_filename = f"{current_user.username}_{int(time.time())}_{filename}"
        file_path       = os.path.join(app.config['PROFILE_PICS_FOLDER'], unique_filename)

        if m and m.profile_picture:
            old_pic  = m.profile_picture.split('/')[-1]
            old_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], secure_filename(old_pic))
            if os.path.exists(old_path):
                os.remove(old_path)

        file.save(file_path)
        file_url          = url_for('profile_picture', filename=unique_filename)
        m.profile_picture = file_url
        db.session.commit()
        return jsonify({'url': file_url})
    except Exception as e:
        app.logger.error(f"Error uploading profile picture: {e}")
        return jsonify({'error': f'Failed to upload: {e}'}), 500


# ─────────────────────────────────────────────
# CUSTOM SOUNDS
# ─────────────────────────────────────────────

@app.route('/custom_sounds/<filename>')
@login_required
def custom_sound_file(filename):
    safe = secure_filename(filename)
    if safe != filename:
        abort(400)
    return send_from_directory(app.config['SOUNDS_FOLDER'], safe)


@app.route('/get_user_sounds')
@login_required
def get_user_sounds():
    m = get_user_model(current_user.username)
    return jsonify({
        'sound_message': m.sound_message or None,
        'sound_calling': m.sound_calling or None,
    })


@app.route('/upload_sound/<sound_type>', methods=['POST'])
@login_required
def upload_sound(sound_type):
    if sound_type not in ('message', 'calling'):
        return jsonify({'error': 'Invalid sound type'}), 400

    size_limit  = 1 * 1024 * 1024 if sound_type == 'message' else 10 * 1024 * 1024
    limit_label = '1 MB' if sound_type == 'message' else '10 MB'

    try:
        m = get_user_model(current_user.username)

        if request.is_json:
            data = request.get_json()
            if data.get('remove'):
                col = f'sound_{sound_type}'
                old_url = getattr(m, col)
                if old_url:
                    old_file = old_url.split('/')[-1]
                    old_path = os.path.join(app.config['SOUNDS_FOLDER'], secure_filename(old_file))
                    if os.path.exists(old_path):
                        os.remove(old_path)
                    setattr(m, col, None)
                    db.session.commit()
                return jsonify({'success': True})

        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        if not allowed_file(file.filename, ALLOWED_SOUND_EXTENSIONS):
            return jsonify({'error': 'Only MP3, OGG, or WAV files are allowed.'}), 400

        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)
        if file_size > size_limit:
            return jsonify({'error': f'File too large. Maximum size is {limit_label}.'}), 400

        col     = f'sound_{sound_type}'
        old_url = getattr(m, col)
        if old_url:
            old_file = old_url.split('/')[-1]
            old_path = os.path.join(app.config['SOUNDS_FOLDER'], secure_filename(old_file))
            if os.path.exists(old_path):
                os.remove(old_path)

        filename        = secure_filename(file.filename)
        unique_filename = f"{current_user.username}_{sound_type}_{int(time.time())}_{filename}"
        file_path       = os.path.join(app.config['SOUNDS_FOLDER'], unique_filename)
        file.save(file_path)

        file_url = url_for('custom_sound_file', filename=unique_filename)
        setattr(m, col, file_url)
        db.session.commit()
        return jsonify({'url': file_url})

    except Exception as e:
        app.logger.error(f"Error uploading sound ({sound_type}): {e}")
        return jsonify({'error': f'Failed to upload: {e}'}), 500


# ─────────────────────────────────────────────
# APPEARANCE — THEME + CUSTOM CSS   ← NEW
# ─────────────────────────────────────────────

@app.route('/settings/theme', methods=['POST'])
@login_required
def set_theme():
    """Persist the user's chosen theme to the DB and update the session."""
    try:
        data  = request.get_json(silent=True) or {}
        theme = data.get('theme', 'kryonix')

        if theme not in ALLOWED_THEMES:
            return jsonify({'error': 'Invalid theme'}), 400

        m = get_user_model(current_user.username)
        m.active_theme = theme
        db.session.commit()

        # Sync session so base.html injects the correct <link> tag immediately
        _load_theme_into_session(m)

        return jsonify({'ok': True})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error setting theme: {e}")
        return jsonify({'error': 'Failed to save theme'}), 500


@app.route('/upload_custom_css', methods=['POST'])
@login_required
def upload_custom_css():
    """Upload a custom CSS file (max 200 KB) and link it to the user's account."""
    try:
        m = get_user_model(current_user.username)

        # ── Remove ──
        if request.is_json:
            data = request.get_json(silent=True) or {}
            if data.get('remove'):
                if m.custom_css_url:
                    old_file = m.custom_css_url.split('/')[-1]
                    old_path = os.path.join(
                        app.config['CUSTOM_CSS_FOLDER'], secure_filename(old_file)
                    )
                    if os.path.exists(old_path):
                        os.remove(old_path)
                m.custom_css_url = None
                m.active_theme   = 'kryonix'   # revert to default
                db.session.commit()
                _load_theme_into_session(m)
                return jsonify({'success': True})

        # ── Upload ──
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
        if ext != 'css':
            return jsonify({'error': 'Only .css files are allowed'}), 400

        # Check size
        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)
        if file_size > MAX_CUSTOM_CSS_BYTES:
            return jsonify({'error': 'File too large (max 200 KB)'}), 400

        # Remove old file if present
        if m.custom_css_url:
            old_file = m.custom_css_url.split('/')[-1]
            old_path = os.path.join(
                app.config['CUSTOM_CSS_FOLDER'], secure_filename(old_file)
            )
            if os.path.exists(old_path):
                os.remove(old_path)

        filename        = secure_filename(file.filename)
        unique_filename = f"{current_user.username}_{int(time.time())}_{filename}"
        file_path       = os.path.join(app.config['CUSTOM_CSS_FOLDER'], unique_filename)
        file.save(file_path)

        css_url          = url_for('custom_css_file', filename=unique_filename)
        m.custom_css_url = css_url
        m.active_theme   = 'custom'
        db.session.commit()
        _load_theme_into_session(m)

        return jsonify({'url': css_url})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error uploading custom CSS: {e}")
        return jsonify({'error': f'Failed to upload: {e}'}), 500


# ─────────────────────────────────────────────
# GROUPS
# ─────────────────────────────────────────────

@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    try:
        data             = request.get_json()
        group_name       = (data.get('name') or '').strip()
        member_usernames = data.get('members', [])

        if not group_name:
            return jsonify({'error': 'Group name is required'}), 400
        if len(group_name) > 50:
            return jsonify({'error': 'Group name must be 50 characters or fewer'}), 400
        if len(member_usernames) < 1:
            return jsonify({'error': 'At least 1 other member is required'}), 400

        m = get_user_model(current_user.username)
        for member in member_usernames:
            if member not in (m.friends or []):
                return jsonify({'error': f'{member} is not your friend'}), 400

        group_id = f"group_{int(time.time())}_{secrets.token_hex(4)}"
        g = GroupChat(id=group_id, name=group_name, creator=current_user.username)
        db.session.add(g)
        db.session.add(GroupMember(group_id=group_id, username=current_user.username))
        for member in member_usernames:
            db.session.add(GroupMember(group_id=group_id, username=member))
        db.session.commit()

        for member in member_usernames:
            if member in user_sids:
                for sid in user_sids[member]:
                    socketio.emit('group_membership_update',
                                  {'action': 'added', 'group_id': group_id, 'group_name': group_name},
                                  room=sid)
        return jsonify({'success': True, 'group_id': group_id, 'group_name': group_name})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating group: {e}")
        return jsonify({'error': 'Failed to create group'}), 500


@app.route('/get_group_info/<group_id>', methods=['GET'])
@login_required
def get_group_info(group_id):
    try:
        g = GroupChat.query.get(group_id)
        if not g:
            return jsonify({'error': 'Group not found'}), 404
        if not user_in_group(current_user.username, group_id):
            return jsonify({'error': 'You are not a member of this group'}), 403

        members_info = []
        for username in get_group_members(group_id):
            um = UserModel.query.get(username)
            if um:
                members_info.append({'username': username, 'profile_picture': um.profile_picture})

        return jsonify({
            'name':       g.name,
            'creator':    g.creator,
            'members':    members_info,
            'is_creator': current_user.username == g.creator,
        })
    except Exception as e:
        app.logger.error(f"Error getting group info: {e}")
        return jsonify({'error': 'Failed to get group info'}), 500


@app.route('/update_group/<group_id>', methods=['POST'])
@login_required
def update_group(group_id):
    try:
        data   = request.get_json()
        action = data.get('action')
        g      = GroupChat.query.get(group_id)

        if not g:
            return jsonify({'error': 'Group not found'}), 404
        if not user_in_group(current_user.username, group_id):
            return jsonify({'error': 'You are not a member of this group'}), 403

        if action == 'rename':
            if current_user.username != g.creator:
                return jsonify({'error': 'Only the creator can rename the group'}), 403
            new_name = (data.get('name') or '').strip()
            if not new_name or len(new_name) > 50:
                return jsonify({'error': 'Invalid group name'}), 400
            g.name = new_name
            db.session.commit()
            for member in get_group_members(group_id):
                if member in user_sids:
                    for sid in user_sids[member]:
                        socketio.emit('group_membership_update',
                                      {'action': 'renamed', 'group_id': group_id, 'group_name': new_name},
                                      room=sid)
            return jsonify({'success': True})

        elif action == 'kick':
            if current_user.username != g.creator:
                return jsonify({'error': 'Only the creator can kick members'}), 403
            member = data.get('member')
            if member == g.creator:
                return jsonify({'error': 'Cannot kick the creator'}), 400
            gm = GroupMember.query.filter_by(group_id=group_id, username=member).first()
            if gm:
                db.session.delete(gm)
                db.session.commit()
                if member in user_sids:
                    for sid in user_sids[member]:
                        socketio.emit('group_membership_update',
                                      {'action': 'removed', 'group_id': group_id},
                                      room=sid)
            return jsonify({'success': True})

        elif action == 'leave':
            if current_user.username == g.creator:
                return jsonify({'error': 'Creators cannot leave — delete the group instead'}), 400
            gm = GroupMember.query.filter_by(group_id=group_id, username=current_user.username).first()
            if gm:
                db.session.delete(gm)
                db.session.commit()
            return jsonify({'success': True})

        elif action == 'add_members':
            if current_user.username != g.creator:
                return jsonify({'error': 'Only the creator can add members'}), 403
            members = data.get('members', [])
            m = get_user_model(current_user.username)
            for member in members:
                if member not in (m.friends or []):
                    return jsonify({'error': f'{member} is not your friend'}), 400
                if not user_in_group(member, group_id):
                    db.session.add(GroupMember(group_id=group_id, username=member))
                    if member in user_sids:
                        for sid in user_sids[member]:
                            socketio.emit('group_membership_update',
                                          {'action': 'added', 'group_id': group_id, 'group_name': g.name},
                                          room=sid)
            db.session.commit()
            return jsonify({'success': True})

        return jsonify({'error': 'Invalid action'}), 400

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating group: {e}")
        return jsonify({'error': 'Failed to update group'}), 500


@app.route('/groups', methods=['GET', 'POST'])
@login_required
def groups():
    message      = None
    message_type = None
    username     = current_user.username

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'create_group':
            group_name       = (request.form.get('group_name') or '').strip()
            member_usernames = request.form.getlist('members')
            if not group_name or len(group_name) < 3:
                message, message_type = 'Group name must be at least 3 characters.', 'error'
            else:
                m        = get_user_model(username)
                group_id = f"group_{int(time.time())}_{secrets.token_hex(4)}"
                g        = GroupChat(id=group_id, name=group_name, creator=username)
                db.session.add(g)
                db.session.add(GroupMember(group_id=group_id, username=username))
                for member in member_usernames:
                    if member in (m.friends or []):
                        db.session.add(GroupMember(group_id=group_id, username=member))
                db.session.commit()
                message, message_type = f"Group '{group_name}' created!", 'success'

        elif action == 'leave_group':
            group_id = request.form.get('group_id')
            g = GroupChat.query.get(group_id)
            if g and user_in_group(username, group_id) and g.creator != username:
                gm = GroupMember.query.filter_by(group_id=group_id, username=username).first()
                if gm:
                    db.session.delete(gm)
                    db.session.commit()
                message, message_type = 'Left group.', 'success'
            else:
                message, message_type = 'Cannot leave this group.', 'error'

        elif action == 'add_member':
            group_id   = request.form.get('group_id')
            new_member = (request.form.get('new_member') or '').strip()
            g = GroupChat.query.get(group_id)
            if g and g.creator == username and not user_in_group(new_member, group_id):
                m = get_user_model(username)
                if new_member in (m.friends or []):
                    db.session.add(GroupMember(group_id=group_id, username=new_member))
                    db.session.commit()
                    message, message_type = f"Added '{new_member}'.", 'success'
                else:
                    message, message_type = f"'{new_member}' is not your friend.", 'error'
            else:
                message, message_type = 'Cannot add this member.', 'error'

    m = get_user_model(username)
    user_groups = []
    for gm in GroupMember.query.filter_by(username=username).all():
        g = gm.group
        user_groups.append({
            'id':         g.id,
            'name':       g.name,
            'creator':    g.creator,
            'members':    get_group_members(g.id),
            'created_at': g.created_at.isoformat(),
        })

    return render_template('groups.html',
                           current_user=current_user,
                           user_groups=user_groups,
                           friends_list=m.friends or [],
                           message=message,
                           message_type=message_type)


# ─────────────────────────────────────────────
# FRIENDS
# ─────────────────────────────────────────────

@app.route('/friends', methods=['GET', 'POST'])
@login_required
def friends():
    username = current_user.username
    m        = get_user_model(username)
    message  = None
    message_type = None

    if request.method == 'POST':
        action          = request.form.get('action')
        target_username = (request.form.get('target_username') or '').strip()

        if not target_username:
            message, message_type = "Target username is required.", "error"
        elif target_username == username:
            message, message_type = "You cannot perform this action on yourself.", "error"
        else:
            tm = get_user_model(target_username)
            if not tm:
                message, message_type = f"User '{target_username}' not found.", "error"
            else:
                try:
                    if action == 'send_request':
                        if target_username in (m.friends or []) or \
                           target_username in (m.requests or []) or \
                           username in (tm.requests or []):
                            message, message_type = "Request already pending or already friends.", "error"
                        elif target_username in (m.blocked or []):
                            message, message_type = f"You have blocked '{target_username}'.", "error"
                        elif username in (tm.blocked or []):
                            message, message_type = f"You are blocked by '{target_username}'.", "error"
                        else:
                            reqs = list(tm.requests or [])
                            reqs.append(username)
                            tm.requests = reqs
                            db.session.commit()
                            message, message_type = f"Friend request sent to '{target_username}'.", "success"
                            pending_count = len(tm.requests)
                            if target_username in user_sids:
                                for sid in user_sids[target_username]:
                                    socketio.emit('friend_request_received',
                                                  {'from': username, 'pending_count': pending_count},
                                                  room=sid)

                    elif action == 'accept_request':
                        if username not in (tm.requests or []) and target_username in (m.requests or []):
                            my_friends = list(m.friends or [])
                            my_reqs    = list(m.requests or [])
                            if target_username not in my_friends:
                                my_friends.append(target_username)
                            my_reqs = [r for r in my_reqs if r != target_username]
                            m.friends  = my_friends
                            m.requests = my_reqs

                            their_friends = list(tm.friends or [])
                            if username not in their_friends:
                                their_friends.append(username)
                            tm.friends = their_friends
                            db.session.commit()
                            message, message_type = f"Accepted friend request from '{target_username}'.", "success"

                            my_pic    = m.profile_picture
                            their_pic = tm.profile_picture
                            remaining = len(m.requests)
                            if username in user_sids:
                                for sid in user_sids[username]:
                                    socketio.emit('friend_request_accepted',
                                                  {'username': target_username, 'profile_picture': their_pic, 'pending_count': remaining},
                                                  room=sid)
                            if target_username in user_sids:
                                for sid in user_sids[target_username]:
                                    socketio.emit('friend_request_accepted',
                                                  {'username': username, 'profile_picture': my_pic, 'pending_count': 0},
                                                  room=sid)
                        else:
                            message, message_type = f"No pending request from '{target_username}'.", "error"

                    elif action == 'decline_request':
                        my_reqs = list(m.requests or [])
                        if target_username in my_reqs:
                            my_reqs.remove(target_username)
                            m.requests = my_reqs
                            db.session.commit()
                            message, message_type = f"Declined friend request from '{target_username}'.", "success"
                        else:
                            message, message_type = f"No pending request from '{target_username}'.", "error"

                    elif action == 'remove_friend':
                        my_friends    = list(m.friends or [])
                        their_friends = list(tm.friends or [])
                        if target_username in my_friends:
                            my_friends.remove(target_username)
                            m.friends = my_friends
                            if username in their_friends:
                                their_friends.remove(username)
                                tm.friends = their_friends
                            db.session.commit()
                            message, message_type = f"Removed '{target_username}' from friends.", "success"
                            for notified, removed in [(username, target_username), (target_username, username)]:
                                if notified in user_sids:
                                    for sid in user_sids[notified]:
                                        socketio.emit('friend_removed', {'username': removed}, room=sid)
                        else:
                            message, message_type = f"'{target_username}' is not in your friends list.", "error"

                    elif action == 'block_user':
                        my_blocked = list(m.blocked or [])
                        if target_username not in my_blocked:
                            my_blocked.append(target_username)
                            m.blocked = my_blocked
                            my_friends = list(m.friends or [])
                            if target_username in my_friends:
                                my_friends.remove(target_username)
                                m.friends = my_friends
                                their_friends = list(tm.friends or [])
                                if username in their_friends:
                                    their_friends.remove(username)
                                    tm.friends = their_friends
                            my_reqs = list(m.requests or [])
                            if target_username in my_reqs:
                                my_reqs.remove(target_username)
                                m.requests = my_reqs
                            their_reqs = list(tm.requests or [])
                            if username in their_reqs:
                                their_reqs.remove(username)
                                tm.requests = their_reqs
                            db.session.commit()
                            message, message_type = f"Blocked '{target_username}'.", "success"
                        else:
                            message, message_type = f"'{target_username}' is already blocked.", "error"

                    elif action == 'unblock_user':
                        my_blocked = list(m.blocked or [])
                        if target_username in my_blocked:
                            my_blocked.remove(target_username)
                            m.blocked = my_blocked
                            db.session.commit()
                            message, message_type = f"Unblocked '{target_username}'.", "success"
                        else:
                            message, message_type = f"'{target_username}' is not blocked.", "error"

                    else:
                        message, message_type = "Invalid action.", "error"

                except Exception as e:
                    db.session.rollback()
                    message, message_type = f"An error occurred: {e}", "error"
                    app.logger.error(f"Error in friends route: {e}")

    m = get_user_model(username)
    user_data_dict = {
        'friends':  m.friends or [],
        'requests': m.requests or [],
        'blocked':  m.blocked or [],
    }
    return render_template('friends.html',
                           current_user=current_user,
                           user_data=user_data_dict,
                           message=message,
                           message_type=message_type)


# ─────────────────────────────────────────────
# SETTINGS
# ─────────────────────────────────────────────

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    m        = get_user_model(current_user.username)
    message  = None
    message_type = None

    if request.method == 'POST':
        section = request.form.get('section', 'account')

        if section == 'theme':
            new_primary = request.form.get('primary_color')
            new_accent  = request.form.get('accent_color')
            if new_primary and new_accent:
                if not re.match(r'^#[0-9a-fA-F]{6}$', new_primary) or \
                   not re.match(r'^#[0-9a-fA-F]{6}$', new_accent):
                    message, message_type = "Invalid colour format.", "error"
                else:
                    m.settings = {**(m.settings or {}), 'primary_color': new_primary, 'accent_color': new_accent}
                    db.session.commit()
                    session['primary_color'] = new_primary
                    session['accent_color']  = new_accent
                    message, message_type = "Theme settings updated successfully!", "success"
            else:
                message, message_type = "Both colours are required.", "error"

        elif section == 'account':
            new_username     = (request.form.get('username') or '').strip()
            new_email        = (request.form.get('email') or '').strip().lower()
            current_password = request.form.get('current_password', '')
            new_password     = request.form.get('new_password', '')

            if new_username and new_username != current_user.username:
                if len(new_username) < 3:
                    message, message_type = "Username must be at least 3 characters.", "error"
                elif not re.match(r'^[\w.-]+$', new_username):
                    message, message_type = "Username may only contain letters, numbers, dots, dashes, and underscores.", "error"
                elif UserModel.query.get(new_username):
                    message, message_type = "Username already taken.", "error"
                else:
                    old_username = current_user.username
                    for um in UserModel.query.all():
                        changed = False
                        for attr in ('friends', 'requests', 'blocked'):
                            lst = list(getattr(um, attr) or [])
                            if old_username in lst:
                                lst[lst.index(old_username)] = new_username
                                setattr(um, attr, lst)
                                changed = True
                        if changed:
                            db.session.flush()
                    Message.query.filter_by(sender_username=old_username).update({'sender_username': new_username})
                    GroupMember.query.filter_by(username=old_username).update({'username': new_username})
                    GroupChat.query.filter_by(creator=old_username).update({'creator': new_username})
                    m.username = new_username
                    db.session.commit()
                    logout_user()
                    flash('Username changed successfully! Please log in again.', 'success')
                    return redirect(url_for('login'))

            if new_email and new_email != m.email:
                if '@' not in new_email or '.' not in new_email.split('@')[-1]:
                    message, message_type = "Invalid email format.", "error"
                elif UserModel.query.filter_by(email=new_email).first():
                    message, message_type = "Email already in use.", "error"
                else:
                    m.email = new_email
                    db.session.commit()
                    message, message_type = "Email updated successfully!", "success"

            if current_password and new_password:
                if not check_password_hash(m.password_hash, current_password):
                    message, message_type = "Current password is incorrect.", "error"
                elif len(new_password) < 6:
                    message, message_type = "New password must be at least 6 characters.", "error"
                else:
                    m.password_hash = generate_password_hash(new_password)
                    db.session.commit()
                    message, message_type = "Password changed successfully!", "success"

    # Always reload from DB so the page reflects current state
    m = get_user_model(current_user.username)

    # Keep theme session in sync whenever settings page is loaded
    _load_theme_into_session(m)

    return render_template('settings.html',
                           current_user=current_user,
                           settings=m.settings or {},
                           user_data={
                               'email':          m.email,
                               'username':       m.username,
                               'profile_picture': m.profile_picture,
                               'sound_message':  m.sound_message,
                               'sound_calling':  m.sound_calling,
                               'active_theme':   m.active_theme or 'kryonix',    # ← NEW
                               'custom_css_url': m.custom_css_url,               # ← NEW
                           },
                           message=message,
                           message_type=message_type)


# ─────────────────────────────────────────────
# ADMIN
# ─────────────────────────────────────────────

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_page():
    if current_user.username != 'admin':
        abort(403)

    message      = None
    message_type = None

    if request.method == 'POST':
        action          = request.form.get('action')
        target_username = (request.form.get('target_username') or '').strip()
        target_email    = (request.form.get('target_email') or '').strip()

        if action in ('delete_user', 'timeout', 'untimeout', 'ban_user', 'change_password'):
            tm = UserModel.query.get(target_username) if target_username else None
            if not tm:
                message, message_type = f"User '{target_username}' not found.", "error"
            elif target_username == 'admin':
                message, message_type = "Cannot perform this action on admin.", "error"
            else:
                try:
                    if action == 'delete_user':
                        db.session.delete(tm)
                        db.session.commit()
                        message, message_type = f"User '{target_username}' deleted.", "success"

                    elif action == 'timeout':
                        minutes = int(request.form.get('minutes', 0))
                        if minutes > 0:
                            tm.timeout_until = datetime.utcnow() + timedelta(minutes=minutes)
                            db.session.commit()
                            message, message_type = f"User '{target_username}' timed out for {minutes} minutes.", "success"
                        else:
                            message, message_type = "Invalid timeout duration.", "error"

                    elif action == 'untimeout':
                        tm.timeout_until = None
                        db.session.commit()
                        message, message_type = f"User '{target_username}' un-timed out.", "success"

                    elif action == 'ban_user':
                        if not BannedEmail.query.filter_by(email=tm.email).first():
                            db.session.add(BannedEmail(email=tm.email))
                            db.session.commit()
                            message, message_type = f"User '{target_username}' banned.", "success"
                        else:
                            message, message_type = "Email already banned.", "error"

                    elif action == 'change_password':
                        new_pw = request.form.get('new_password', '')
                        if len(new_pw) < 6:
                            message, message_type = "Password must be at least 6 characters.", "error"
                        else:
                            tm.password_hash = generate_password_hash(new_pw)
                            db.session.commit()
                            message, message_type = f"Password for '{target_username}' changed.", "success"

                except Exception as e:
                    db.session.rollback()
                    message, message_type = f"An error occurred: {e}", "error"
                    app.logger.error(f"Admin action error: {e}")

        elif action == 'unban_email':
            be = BannedEmail.query.filter_by(email=target_email).first()
            if be:
                db.session.delete(be)
                db.session.commit()
                message, message_type = f"Email '{target_email}' unbanned.", "success"
            else:
                message, message_type = f"Email '{target_email}' not found in banned list.", "error"
        else:
            message, message_type = "Invalid admin action.", "error"

    users       = UserModel.query.filter(UserModel.username != 'admin').all()
    banned_list = [b.email for b in BannedEmail.query.all()]
    return render_template('admin.html',
                           current_user=current_user,
                           users=users,
                           banned_list=banned_list,
                           message=message,
                           message_type=message_type)


# ─────────────────────────────────────────────
# MISC API
# ─────────────────────────────────────────────

@app.route('/get_pending_requests_count')
@login_required
def get_pending_requests_count():
    m = get_user_model(current_user.username)
    return jsonify({'count': len(m.requests or [])})


@app.route('/get_user_profiles', methods=['POST'])
@login_required
def get_user_profiles():
    try:
        data      = request.get_json()
        usernames = data.get('usernames', [])
        profiles  = {}
        for username in usernames:
            um = UserModel.query.get(username)
            if um:
                profiles[username] = {'profile_picture': um.profile_picture}
        return jsonify(profiles)
    except Exception as e:
        app.logger.error(f"Error getting user profiles: {e}")
        return jsonify({'error': 'Failed to get profiles'}), 500


@app.route('/get_contacts_order', methods=['GET'])
@login_required
def get_contacts_order():
    try:
        username = current_user.username
        m        = get_user_model(username)
        if not m:
            return jsonify({'error': 'User data not found'}), 404

        contacts = []

        for friend in (m.friends or []):
            room_name = '-'.join(sorted([username, friend]))
            last_msg  = (Message.query
                         .filter_by(room=room_name)
                         .order_by(Message.timestamp.desc())
                         .first())
            last_ts   = int(last_msg.timestamp.timestamp() * 1000) if last_msg else 0
            last_time = last_msg.timestamp.isoformat()             if last_msg else None
            last_text = last_msg.content                           if last_msg else ''

            contacts.append({
                'id':                     friend,
                'type':                   'direct',
                'last_message_time':      last_time,
                'last_message_timestamp': last_ts,
                'last_message_text':      last_text,
                'unread_count':           0,
            })

        for gm in GroupMember.query.filter_by(username=username).all():
            g        = gm.group
            last_msg = (Message.query
                        .filter_by(room=g.id)
                        .order_by(Message.timestamp.desc())
                        .first())
            last_ts   = int(last_msg.timestamp.timestamp() * 1000) if last_msg else 0
            last_time = last_msg.timestamp.isoformat()             if last_msg else None
            last_text = last_msg.content                           if last_msg else ''

            contacts.append({
                'id':                     g.id,
                'type':                   'group',
                'name':                   g.name,
                'last_message_time':      last_time,
                'last_message_timestamp': last_ts,
                'last_message_text':      last_text,
                'unread_count':           0,
            })

        contacts.sort(key=lambda x: x.get('last_message_timestamp', 0), reverse=True)
        return jsonify({'contacts': contacts})
    except Exception as e:
        app.logger.error(f"Error getting contacts order: {e}")
        return jsonify({'error': 'Failed to get contacts order'}), 500


# ─────────────────────────────────────────────
# SOCKET.IO EVENTS
# ─────────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    try:
        if not current_user.is_authenticated:
            return False
        username = current_user.username
        if username not in user_sids:
            user_sids[username] = set()
        user_sids[username].add(request.sid)
        update_user_status(username, 'online')
        emit('user_status_update', {'username': username, 'status': 'online'}, broadcast=True)
    except Exception as e:
        app.logger.error(f"Error in handle_connect: {e}")


@socketio.on('disconnect')
def handle_disconnect():
    try:
        if not current_user.is_authenticated:
            return
        username = current_user.username
        if username in user_sids:
            user_sids[username].discard(request.sid)
            if not user_sids[username]:
                del user_sids[username]
                update_user_status(username, 'offline')
                emit('user_status_update', {'username': username, 'status': 'offline'}, broadcast=True)
    except Exception as e:
        app.logger.error(f"Error in handle_disconnect: {e}")


@socketio.on('user_connected')
def handle_user_connected():
    try:
        if not current_user.is_authenticated:
            return
        username = current_user.username
        if username not in user_sids:
            user_sids[username] = set()
        user_sids[username].add(request.sid)
        update_user_status(username, 'online')
        emit('user_status_update', {'username': username, 'status': 'online'}, broadcast=True)
    except Exception as e:
        app.logger.error(f"Error in handle_user_connected: {e}")


@socketio.on('request_statuses')
def handle_request_statuses():
    try:
        statuses = {}
        for u, sids in user_sids.items():
            if sids:
                statuses[u] = {'status': 'online'}
        emit('all_statuses', statuses)
    except Exception as e:
        app.logger.error(f"Error in handle_request_statuses: {e}")


@socketio.on('join')
def handle_join(data):
    try:
        if not current_user.is_authenticated:
            return
        room     = data['room']
        username = current_user.username

        if room.startswith('group_'):
            if not user_in_group(username, room):
                emit('error', {'message': 'You are not a member of this group'})
                return
        else:
            parts = room.split('-')
            if len(parts) == 2:
                other = parts[1] if parts[0] == username else parts[0]
                m = get_user_model(username)
                if other not in (m.friends or []):
                    emit('error', {'message': 'You are not friends with this user'})
                    return

        join_room(room)
    except Exception as e:
        app.logger.error(f"Error in handle_join: {e}")
        emit('error', {'message': 'Failed to join room'})


@socketio.on('leave')
def handle_leave(data):
    try:
        leave_room(data['room'])
    except Exception as e:
        app.logger.error(f"Error in handle_leave: {e}")


@socketio.on('send_message')
def handle_send_message(data):
    try:
        if not current_user.is_authenticated:
            return
        username = current_user.username
        if current_user.is_timed_out:
            emit('error', {'message': 'You are timed out and cannot send messages.'})
            return
        if not check_rate_limit(username):
            emit('error', {'message': 'You are sending messages too fast. Please slow down.'})
            return

        room = data.get('room')
        msg  = data.get('msg', '').strip()
        if not msg or not room:
            return

        # Basic HTML tag whitelist — allow img, video, a, em only
        _ALLOWED = re.compile(
            r'<(?!(/?(img|video|a|em|source)\b))[^>]+>',
            re.IGNORECASE
        )
        if not re.search(r'<(img|video|a)\b', msg, re.IGNORECASE):
            if len(msg) > MAX_MESSAGE_LENGTH:
                emit('error', {'message': f'Message too long (max {MAX_MESSAGE_LENGTH} characters).'})
                return

        # Authorization
        if room.startswith('group_'):
            if not user_in_group(username, room):
                emit('error', {'message': 'You are not a member of this group'})
                return
        else:
            parts = room.split('-')
            if len(parts) != 2:
                emit('error', {'message': 'Invalid room'})
                return
            other = parts[1] if parts[0] == username else parts[0]
            m = get_user_model(username)
            if other not in (m.friends or []):
                emit('error', {'message': 'You are not friends with this user'})
                return
            tm = get_user_model(other)
            if tm and username in (tm.blocked or []):
                emit('error', {'message': 'You are blocked by this user'})
                return

        now      = datetime.utcnow()
        msg_id   = f"{username}_{int(now.timestamp() * 1000)}_{secrets.token_hex(4)}"
        time_str = now.strftime('%H:%M')

        reply_to = data.get('reply_to')
        if reply_to:
            reply_to = {
                'id':       reply_to.get('id', ''),
                'username': reply_to.get('username', ''),
                'msg':      reply_to.get('msg', '')[:200],
            }

        message_data = {
            'id':       msg_id,
            'username': username,
            'msg':      msg,
            'time':     time_str,
            'room':     room,
        }
        if reply_to:
            message_data['reply_to'] = reply_to

        add_message_to_db(room, message_data)
        emit('message', message_data, room=room)

    except Exception as e:
        app.logger.error(f"Error in handle_send_message: {e}")
        emit('error', {'message': 'Failed to send message'})


@socketio.on('edit_message')
def handle_edit_message(data):
    try:
        if not current_user.is_authenticated:
            return
        username   = current_user.username
        message_id = data.get('message_id')
        new_text   = (data.get('new_text') or '').strip()
        room       = data.get('room')

        if not message_id or not new_text or not room:
            return
        if len(new_text) > MAX_MESSAGE_LENGTH:
            emit('error', {'message': 'Message too long.'})
            return

        msg = Message.query.get(message_id)
        if not msg or msg.sender_username != username:
            emit('error', {'message': 'Cannot edit this message.'})
            return

        tagged = new_text + ' <em>(edited)</em>'
        if update_message_in_db(message_id, tagged):
            emit('message_updated', {'id': message_id, 'new_text': tagged, 'room': room}, room=room)
    except Exception as e:
        app.logger.error(f"Error in handle_edit_message: {e}")


@socketio.on('delete_message')
def handle_delete_message(data):
    try:
        if not current_user.is_authenticated:
            return
        username   = current_user.username
        message_id = data.get('message_id')
        room       = data.get('room')

        msg = Message.query.get(message_id)
        if not msg:
            return
        if msg.sender_username != username and username != 'admin':
            emit('error', {'message': 'Cannot delete this message.'})
            return

        deleted_text = '<em>deleted message</em>'
        if delete_message_in_db(message_id):
            emit('message_updated', {'id': message_id, 'new_text': deleted_text, 'room': room}, room=room)
    except Exception as e:
        app.logger.error(f"Error in handle_delete_message: {e}")


@socketio.on('typing_start')
def handle_typing_start(data):
    try:
        emit('user_typing', {'username': current_user.username, 'is_typing': True},
             room=data['room'], include_self=False)
    except Exception as e:
        app.logger.error(f"Error in handle_typing_start: {e}")


@socketio.on('typing_stop')
def handle_typing_stop(data):
    try:
        emit('user_typing', {'username': current_user.username, 'is_typing': False},
             room=data['room'], include_self=False)
    except Exception as e:
        app.logger.error(f"Error in handle_typing_stop: {e}")


# ─────────────────────────────────────────────
# WEBRTC / CALL EVENTS
# ─────────────────────────────────────────────

@socketio.on('call_user')
def handle_call_user(data):
    try:
        if not current_user.is_authenticated:
            return
        caller    = current_user.username
        callee    = data['callee']
        room      = data['room']
        call_type = data.get('type', 'video')

        if current_user.is_timed_out:
            emit('error', {'message': 'You are timed out.'}, room=request.sid)
            return

        m = get_user_model(caller)
        if callee not in (m.friends or []):
            emit('error', {'message': 'You can only call friends.'}, room=request.sid)
            return

        if callee in user_sids:
            for sid in user_sids[callee]:
                emit('incoming_call', {'caller': caller, 'room': room, 'type': call_type}, room=sid)
        else:
            emit('error', {'message': f'{callee} is not online.'}, room=request.sid)
    except Exception as e:
        app.logger.error(f"Error in handle_call_user: {e}")
        emit('error', {'message': 'Failed to initiate call.'}, room=request.sid)


@socketio.on('answer_call')
def handle_answer_call(data):
    try:
        answerer  = current_user.username
        caller    = data['caller']
        room      = data['room']
        call_type = data['type']
        active_calls[room] = {'caller': caller, 'receiver': answerer, 'type': call_type}
        if caller in user_sids:
            for sid in user_sids[caller]:
                emit('call_answered', {'answerer': answerer, 'room': room}, room=sid)
    except Exception as e:
        app.logger.error(f"Error in handle_answer_call: {e}")


@socketio.on('reject_call')
def handle_reject_call(data):
    try:
        caller = data['caller']
        room   = data['room']
        if caller in user_sids:
            for sid in user_sids[caller]:
                emit('call_rejected', {'rejecter': current_user.username, 'room': room}, room=sid)
    except Exception as e:
        app.logger.error(f"Error in handle_reject_call: {e}")


@socketio.on('end_call')
def handle_end_call(data):
    try:
        username = current_user.username
        room     = data['room']
        if room in active_calls:
            call_info  = active_calls.pop(room)
            other_user = call_info['caller'] if call_info['receiver'] == username else call_info['receiver']
            if other_user in user_sids:
                for sid in user_sids[other_user]:
                    emit('call_ended', {'room': room, 'ended_by': username}, room=sid)
    except Exception as e:
        app.logger.error(f"Error in handle_end_call: {e}")


@socketio.on('webrtc_offer')
def handle_webrtc_offer(data):
    try:
        emit('webrtc_offer', {'offer': data['offer'], 'sender': current_user.username},
             room=data['room'], include_self=False)
    except Exception as e:
        app.logger.error(f"Error in handle_webrtc_offer: {e}")


@socketio.on('webrtc_answer')
def handle_webrtc_answer(data):
    try:
        emit('webrtc_answer', {'answer': data['answer'], 'sender': current_user.username},
             room=data['room'], include_self=False)
    except Exception as e:
        app.logger.error(f"Error in handle_webrtc_answer: {e}")


@socketio.on('webrtc_ice_candidate')
def handle_ice_candidate(data):
    try:
        emit('webrtc_ice_candidate', {'candidate': data['candidate'], 'sender': current_user.username},
             room=data['room'], include_self=False)
    except Exception as e:
        app.logger.error(f"Error in handle_ice_candidate: {e}")


# --- Group Call Events ---

@socketio.on('group_call_start')
def handle_group_call_start(data):
    try:
        username  = current_user.username
        room      = data['room']
        call_type = data.get('type', 'video')

        if current_user.is_timed_out:
            emit('error', {'message': 'You are timed out.'}, room=request.sid)
            return
        if not user_in_group(username, room):
            emit('error', {'message': 'You are not a member of this group.'}, room=request.sid)
            return

        call_room = f'call_{room}'
        if call_room not in active_group_calls:
            active_group_calls[call_room] = {'participants': set(), 'type': call_type, 'room': room}

        existing = list(active_group_calls[call_room]['participants'])
        active_group_calls[call_room]['participants'].add(username)
        join_room(call_room)

        emit('group_call_joined', {'call_room': call_room, 'existing_participants': existing, 'type': call_type},
             room=request.sid)
        emit('group_call_user_joined', {'username': username, 'call_room': call_room},
             room=call_room, include_self=False)

        g       = GroupChat.query.get(room)
        members = get_group_members(room)
        for member in members:
            if member != username and member not in active_group_calls[call_room]['participants']:
                if member in user_sids:
                    for sid in user_sids[member]:
                        emit('incoming_group_call', {
                            'call_room': call_room, 'room': room,
                            'group_name': g.name if g else 'Group',
                            'started_by': username, 'type': call_type,
                            'participant_count': len(active_group_calls[call_room]['participants']),
                        }, room=sid)
    except Exception as e:
        app.logger.error(f"Error in handle_group_call_start: {e}")
        emit('error', {'message': 'Failed to join group call.'}, room=request.sid)


@socketio.on('group_call_leave')
def handle_group_call_leave(data):
    try:
        username  = current_user.username
        call_room = data['call_room']
        if call_room in active_group_calls:
            active_group_calls[call_room]['participants'].discard(username)
            leave_room(call_room)
            emit('group_call_user_left', {'username': username, 'call_room': call_room}, room=call_room)
            if not active_group_calls[call_room]['participants']:
                del active_group_calls[call_room]
    except Exception as e:
        app.logger.error(f"Error in handle_group_call_leave: {e}")


@socketio.on('group_call_reject')
def handle_group_call_reject(data):
    try:
        emit('group_call_rejected', {'username': current_user.username, 'call_room': data['call_room']},
             room=data['call_room'])
    except Exception as e:
        app.logger.error(f"Error in handle_group_call_reject: {e}")


@socketio.on('group_webrtc_offer')
def handle_group_webrtc_offer(data):
    try:
        target = data['target']
        if target in user_sids:
            for sid in user_sids[target]:
                emit('group_webrtc_offer',
                     {'offer': data['offer'], 'sender': current_user.username, 'call_room': data['call_room']},
                     room=sid)
    except Exception as e:
        app.logger.error(f"Error in handle_group_webrtc_offer: {e}")


@socketio.on('group_webrtc_answer')
def handle_group_webrtc_answer(data):
    try:
        target = data['target']
        if target in user_sids:
            for sid in user_sids[target]:
                emit('group_webrtc_answer',
                     {'answer': data['answer'], 'sender': current_user.username, 'call_room': data['call_room']},
                     room=sid)
    except Exception as e:
        app.logger.error(f"Error in handle_group_webrtc_answer: {e}")


@socketio.on('group_webrtc_ice')
def handle_group_webrtc_ice(data):
    try:
        target = data['target']
        if target in user_sids:
            for sid in user_sids[target]:
                emit('group_webrtc_ice',
                     {'candidate': data['candidate'], 'sender': current_user.username, 'call_room': data['call_room']},
                     room=sid)
    except Exception as e:
        app.logger.error(f"Error in handle_group_webrtc_ice: {e}")


# ─────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not UserModel.query.get('admin'):
            db.session.add(UserModel(
                username       = 'admin',
                email          = 'thomas.desmidt1@gmail.com',
                password_hash  = generate_password_hash('admin'),
                friends        = [],
                requests       = [],
                blocked        = [],
                settings       = {'primary_color': '#ff3f81', 'accent_color': '#0f0f0f'},
                status         = 'offline',
                last_seen      = datetime.utcnow(),
                email_verified = True,
                active_theme   = 'kryonix',
            ))
            db.session.commit()
            print("Admin user created. Username: admin / Password: admin")
            print("!!! IMPORTANT: Change admin password immediately !!!")

    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, host="0.0.0.0", port=5001)
