"""
=============================================================================
  KRYONIX — ANDROID API ENDPOINTS
  Add these routes to your existing app.py (or import this file).
  They are JSON-only counterparts to the existing HTML form routes.
=============================================================================

HOW TO ADD:
  1. Copy everything below the dashed line into app.py.
  2. At the top of app.py add:
       from flask import jsonify, request   (already there)
       import firebase_admin
       from firebase_admin import credentials, messaging
  3. pip install firebase-admin
  4. Download your Firebase service-account JSON from Firebase Console
     → Project Settings → Service Accounts → "Generate new private key"
     Save it as  firebase_service_account.json  next to app.py.
  5. Uncomment the firebase_admin.initialize_app() call below.
=============================================================================
"""

# ── Paste from here ────────────────────────────────────────────────────────

import firebase_admin
from firebase_admin import credentials as fb_creds, messaging as fb_messaging

# Initialise Firebase Admin SDK once.
# Make sure firebase_service_account.json is in the same directory as app.py.
_fb_app = None

def get_fb_app():
    global _fb_app
    if _fb_app is None:
        try:
            cred   = fb_creds.Certificate('firebase_service_account.json')
            _fb_app = firebase_admin.initialize_app(cred)
        except Exception as e:
            app.logger.error(f"Firebase init failed: {e}")
    return _fb_app


def send_fcm_notification(token: str, title: str, body: str, data: dict = None):
    """Send a single FCM push to a device token."""
    try:
        get_fb_app()
        message = fb_messaging.Message(
            notification=fb_messaging.Notification(title=title, body=body),
            data={k: str(v) for k, v in (data or {}).items()},
            token=token,
            android=fb_messaging.AndroidConfig(priority='high'),
        )
        fb_messaging.send(message)
    except Exception as e:
        app.logger.error(f"FCM send failed: {e}")


# ── Helper: add fcm_token column to UserModel ─────────────────────────────
# Add this field to the UserModel class in your existing app.py:
#
#   fcm_token = db.Column(db.String(512), nullable=True)
#
# Then run:  flask db upgrade   (or just restart — SQLite will add the column
# automatically if you call db.create_all() on startup).


# ─────────────────────────────────────────────
# AUTH — JSON versions
# ─────────────────────────────────────────────

@app.route('/api/login', methods=['POST'])
def api_login():
    data        = request.get_json(silent=True) or {}
    login_field = (data.get('login_field') or '').strip()
    password    =  data.get('password') or ''

    user = get_user_by_login(login_field)
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid username/email or password.', 'success': False}), 401
    if is_email_banned(user.email):
        return jsonify({'error': 'Your account is banned.', 'success': False}), 403
    if user.is_timed_out:
        return jsonify({'error': f'Account timed out.', 'success': False}), 403

    m = get_user_model(user.username)
    if not m.email_verified:
        code = generate_2fa_code()
        session['verify_code']      = code
        session['verify_email']     = user.email
        session['verify_username']  = user.username
        session['verify_code_time'] = time.time()
        send_2fa_email(user.email, code, subject="Kryonix — Verify Your Email")
        return jsonify({
            'error':        'Email not verified. A code has been sent.',
            'success':      False,
            'redirect':     'verify_email',
            'masked_email': _mask_email(user.email)
        }), 403

    # Issue 2FA code
    code = generate_2fa_code()
    session['login_2fa_code']     = code
    session['login_2fa_username'] = user.username
    session['login_2fa_time']     = time.time()
    send_2fa_email(user.email, code, subject="Kryonix — Login Verification Code")
    return jsonify({
        'success':      False,
        'requires_2fa': True,
        'masked_email': _mask_email(user.email)
    })


@app.route('/api/register', methods=['POST'])
def api_register():
    data     = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    email    = (data.get('email') or '').strip().lower()
    password =  data.get('password') or ''

    if not username or not email or not password:
        return jsonify({'error': 'All fields are required.', 'success': False}), 400
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters.', 'success': False}), 400
    if not re.match(r'^[\w.-]+$', username):
        return jsonify({'error': 'Invalid username characters.', 'success': False}), 400
    if '@' not in email:
        return jsonify({'error': 'Invalid email.', 'success': False}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters.', 'success': False}), 400
    if UserModel.query.get(username):
        return jsonify({'error': 'Username already taken.', 'success': False}), 409
    if UserModel.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered.', 'success': False}), 409
    if is_email_banned(email):
        return jsonify({'error': 'This email is banned.', 'success': False}), 403

    m = UserModel(
        username=username, email=email,
        password_hash=generate_password_hash(password),
        friends=[], requests=[], blocked=[],
        settings={'primary_color': '#0f0f0f', 'accent_color': '#ff3f81'},
        status='offline', last_seen=datetime.utcnow(),
        email_verified=False, active_theme='kryonix',
    )
    db.session.add(m)
    db.session.commit()

    code = generate_2fa_code()
    session['verify_code']      = code
    session['verify_email']     = email
    session['verify_username']  = username
    session['verify_code_time'] = time.time()
    send_2fa_email(email, code, subject="Kryonix — Verify Your Email")
    return jsonify({
        'success':      True,
        'redirect':     'verify_email',
        'masked_email': _mask_email(email)
    })


@app.route('/api/verify-email', methods=['POST'])
def api_verify_email():
    data    = request.get_json(silent=True) or {}
    entered = (data.get('code') or '').strip()
    stored  = session.get('verify_code')
    issued  = session.get('verify_code_time', 0)

    if time.time() - issued > 600:
        return jsonify({'error': 'Code expired.', 'success': False}), 400
    if entered != stored:
        return jsonify({'error': 'Incorrect code.', 'success': False}), 400

    username = session.pop('verify_username', None)
    for k in ('verify_code', 'verify_email', 'verify_code_time'):
        session.pop(k, None)
    m = get_user_model(username)
    if m:
        m.email_verified = True
        db.session.commit()
    return jsonify({'success': True})


@app.route('/api/verify-email/resend')
def api_resend_verify_email():
    if 'verify_email' not in session:
        return jsonify({'error': 'No pending verification.'}), 400
    code = generate_2fa_code()
    session['verify_code']      = code
    session['verify_code_time'] = time.time()
    send_2fa_email(session['verify_email'], code, subject="Kryonix — Verify Your Email")
    return jsonify({'success': True})


@app.route('/api/verify-login', methods=['POST'])
def api_verify_login():
    data    = request.get_json(silent=True) or {}
    entered = (data.get('code') or '').strip()
    stored  = session.get('login_2fa_code')
    issued  = session.get('login_2fa_time', 0)

    if time.time() - issued > 600:
        for k in ('login_2fa_code', 'login_2fa_username', 'login_2fa_time'):
            session.pop(k, None)
        return jsonify({'error': 'Code expired.', 'success': False}), 400
    if entered != stored:
        return jsonify({'error': 'Incorrect code.', 'success': False}), 400

    username = session.pop('login_2fa_username')
    for k in ('login_2fa_code', 'login_2fa_time'):
        session.pop(k, None)
    m = get_user_model(username)
    if not m:
        return jsonify({'error': 'User not found.', 'success': False}), 404

    user = User(m)
    login_user(user)
    update_user_status(username, 'online')
    _load_theme_into_session(m)
    return jsonify({'success': True, 'username': username})


@app.route('/api/verify-login/resend')
def api_resend_login_code():
    username = session.get('login_2fa_username')
    if not username:
        return jsonify({'error': 'No pending login.'}), 400
    m = get_user_model(username)
    if not m:
        return jsonify({'error': 'User not found.'}), 404
    code = generate_2fa_code()
    session['login_2fa_code'] = code
    session['login_2fa_time'] = time.time()
    send_2fa_email(m.email, code, subject="Kryonix — Login Verification Code")
    return jsonify({'success': True})


@app.route('/api/logout')
@login_required
def api_logout():
    update_user_status(current_user.username, 'offline')
    logout_user()
    return jsonify({'success': True})


# ─────────────────────────────────────────────
# PROFILE / SETTINGS
# ─────────────────────────────────────────────

@app.route('/api/me')
@login_required
def api_me():
    m = get_user_model(current_user.username)
    return jsonify({
        'username':        m.username,
        'email':           m.email,
        'profile_picture': m.profile_picture,
        'status':          m.status,
        'active_theme':    m.active_theme,
    })


@app.route('/api/settings')
@login_required
def api_get_settings():
    m = get_user_model(current_user.username)
    return jsonify({
        'username':        m.username,
        'email':           m.email,
        'profile_picture': m.profile_picture,
        'sound_message':   m.sound_message,
        'sound_calling':   m.sound_calling,
        'active_theme':    m.active_theme or 'kryonix',
        'custom_css_url':  m.custom_css_url,
    })


@app.route('/api/settings/account', methods=['POST'])
@login_required
def api_update_account():
    data             = request.get_json(silent=True) or {}
    new_username     = (data.get('username') or '').strip()
    new_email        = (data.get('email') or '').strip().lower()
    current_password =  data.get('current_password') or ''
    new_password     =  data.get('new_password') or ''

    m = get_user_model(current_user.username)

    if new_email and new_email != m.email:
        if UserModel.query.filter_by(email=new_email).first():
            return jsonify({'error': 'Email already in use.', 'success': False}), 409
        m.email = new_email
        db.session.commit()

    if current_password and new_password:
        if not check_password_hash(m.password_hash, current_password):
            return jsonify({'error': 'Current password is incorrect.', 'success': False}), 401
        if len(new_password) < 6:
            return jsonify({'error': 'New password too short.', 'success': False}), 400
        m.password_hash = generate_password_hash(new_password)
        db.session.commit()

    return jsonify({'success': True})


# ─────────────────────────────────────────────
# FRIENDS — JSON
# ─────────────────────────────────────────────

@app.route('/api/friends', methods=['GET'])
@login_required
def api_get_friends():
    m = get_user_model(current_user.username)
    return jsonify({
        'friends':  m.friends  or [],
        'requests': m.requests or [],
        'blocked':  m.blocked  or [],
    })


@app.route('/api/friends', methods=['POST'])
@login_required
def api_friend_action():
    data            = request.get_json(silent=True) or {}
    action          = data.get('action', '')
    target_username = (data.get('target_username') or '').strip()

    username = current_user.username
    if not target_username or target_username == username:
        return jsonify({'error': 'Invalid target.', 'success': False}), 400

    m  = get_user_model(username)
    tm = get_user_model(target_username)
    if not tm:
        return jsonify({'error': f"User '{target_username}' not found.", 'success': False}), 404

    if action == 'send_request':
        if target_username in (m.friends or []):
            return jsonify({'error': 'Already friends.', 'success': False}), 400
        if username in (tm.blocked or []):
            return jsonify({'error': 'Cannot send request.', 'success': False}), 403
        reqs = list(tm.requests or [])
        if username not in reqs:
            reqs.append(username)
            tm.requests = reqs
            db.session.commit()
        # Socket notification
        if target_username in user_sids:
            for sid in user_sids[target_username]:
                socketio.emit('friend_request_received',
                              {'from': username, 'pending_count': len(tm.requests)}, room=sid)
        # FCM notification
        if hasattr(tm, 'fcm_token') and tm.fcm_token:
            send_fcm_notification(
                tm.fcm_token,
                title="New Friend Request",
                body=f"{username} sent you a friend request",
                data={'type': 'friend_request', 'from': username}
            )
        return jsonify({'success': True})

    elif action == 'accept_request':
        if target_username not in (m.requests or []):
            return jsonify({'error': 'No pending request.', 'success': False}), 400
        my_friends    = list(m.friends or [])
        my_reqs       = [r for r in (m.requests or []) if r != target_username]
        their_friends = list(tm.friends or [])
        if target_username not in my_friends: my_friends.append(target_username)
        if username not in their_friends:     their_friends.append(username)
        m.friends  = my_friends
        m.requests = my_reqs
        tm.friends = their_friends
        db.session.commit()
        for notified, added in [(username, target_username), (target_username, username)]:
            if notified in user_sids:
                for sid in user_sids[notified]:
                    socketio.emit('friend_request_accepted', {'username': added}, room=sid)
        return jsonify({'success': True})

    elif action == 'decline_request':
        my_reqs = [r for r in (m.requests or []) if r != target_username]
        m.requests = my_reqs
        db.session.commit()
        return jsonify({'success': True})

    elif action == 'remove_friend':
        my_friends    = [f for f in (m.friends or []) if f != target_username]
        their_friends = [f for f in (tm.friends or []) if f != username]
        m.friends  = my_friends
        tm.friends = their_friends
        db.session.commit()
        for notified, removed in [(username, target_username), (target_username, username)]:
            if notified in user_sids:
                for sid in user_sids[notified]:
                    socketio.emit('friend_removed', {'username': removed}, room=sid)
        return jsonify({'success': True})

    elif action == 'block_user':
        my_blocked = list(m.blocked or [])
        if target_username not in my_blocked:
            my_blocked.append(target_username)
        m.blocked  = my_blocked
        m.friends  = [f for f in (m.friends  or []) if f != target_username]
        tm.friends = [f for f in (tm.friends or []) if f != username]
        db.session.commit()
        return jsonify({'success': True})

    elif action == 'unblock_user':
        m.blocked = [b for b in (m.blocked or []) if b != target_username]
        db.session.commit()
        return jsonify({'success': True})

    return jsonify({'error': 'Invalid action.', 'success': False}), 400


# ─────────────────────────────────────────────
# FCM TOKEN REGISTRATION
# ─────────────────────────────────────────────

@app.route('/api/register_fcm_token', methods=['POST'])
@login_required
def api_register_fcm_token():
    data  = request.get_json(silent=True) or {}
    token = data.get('token', '').strip()
    if not token:
        return jsonify({'error': 'No token provided.'}), 400
    m = get_user_model(current_user.username)
    # Make sure UserModel has a fcm_token column (see note above).
    if hasattr(m, 'fcm_token'):
        m.fcm_token = token
        db.session.commit()
    return jsonify({'success': True})


# ─────────────────────────────────────────────
# HOOK EXISTING send_message TO ALSO PUSH FCM
# ─────────────────────────────────────────────
# In your existing handle_send_message socket handler, after calling
# emit('message', message_data, room=room), add:
#
#   if not room.startswith('group_'):
#       parts = room.split('-')
#       recipient = parts[1] if parts[0] == username else parts[0]
#       rm = get_user_model(recipient)
#       if rm and hasattr(rm, 'fcm_token') and rm.fcm_token:
#           send_fcm_notification(
#               rm.fcm_token,
#               title=username,
#               body=strip_tags(msg)[:100],
#               data={
#                   'type': 'message', 'sender': username,
#                   'content': strip_tags(msg)[:100],
#                   'room_id': room, 'room_type': 'direct', 'room_name': username
#               }
#           )
