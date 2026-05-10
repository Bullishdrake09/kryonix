// Kryonix Chat - Node.js Version
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Sequelize, DataTypes, Op } = require('sequelize');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const multer = require('multer');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// ── Configuration ─────────────────────────────────────────────
const PORT = process.env.PORT || 5001;
const SECRET_KEY = process.env.SECRET_KEY || crypto.randomBytes(32).toString('hex');

const DB_URI = process.env.DATABASE_URL || 'sqlite://chat.db';
const UPLOAD_FOLDER = 'uploads';
const PROFILE_PICS_FOLDER = 'profile_pics';
const SOUNDS_FOLDER = 'custom_sounds';
const CUSTOM_CSS_FOLDER = 'custom_css';
const MAX_CONTENT_LENGTH = 16 * 1024 * 1024;

const MAIL_SERVER = process.env.MAIL_SERVER || 'smtp.gmail.com';
const MAIL_PORT = parseInt(process.env.MAIL_PORT || '587');
const MAIL_USERNAME = process.env.MAIL_USERNAME || 'thomas.desmidt1@gmail.com';
const MAIL_PASSWORD = process.env.MAIL_PASSWORD || 'qhoprwfspjhuciwu';

const ALLOWED_IMAGE_EXTENSIONS = ['png', 'jpg', 'jpeg', 'gif', 'webp'];
const ALLOWED_VIDEO_EXTENSIONS = ['mp4', 'webm', 'ogg', 'mov'];
const ALLOWED_SOUND_EXTENSIONS = ['mp3', 'ogg', 'wav'];
const ALLOWED_THEMES = ['kryonix', 'dark', 'light', 'custom'];
const MAX_CUSTOM_CSS_BYTES = 200 * 1024;

const RATE_LIMIT_MESSAGES = 10;
const RATE_LIMIT_WINDOW = 5;
const MESSAGES_PER_PAGE = 50;
const MAX_MESSAGE_LENGTH = 3000;

// Create folders if they don't exist
[UPLOAD_FOLDER, PROFILE_PICS_FOLDER, SOUNDS_FOLDER, CUSTOM_CSS_FOLDER].forEach(folder => {
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
});

// ── Database Setup ─────────────────────────────────────────────
const sequelize = new Sequelize(DB_URI, {
    dialect: 'sqlite',
    storage: './chat.db',
    logging: false
});

// User Model
const User = sequelize.define('User', {
    username: { type: DataTypes.STRING(80), primaryKey: true },
    email: { type: DataTypes.STRING(120), unique: true, allowNull: false },
    passwordHash: { type: DataTypes.STRING(256), allowNull: false, field: 'password_hash' },
    friends: { type: DataTypes.JSON, defaultValue: [] },
    requests: { type: DataTypes.JSON, defaultValue: [] },
    blocked: { type: DataTypes.JSON, defaultValue: [] },
    settings: { type: DataTypes.JSON, defaultValue: { primary_color: '#0f0f0f', accent_color: '#ff3f81' } },
    timeoutUntil: { type: DataTypes.DATE, field: 'timeout_until' },
    status: { type: DataTypes.STRING(20), defaultValue: 'offline' },
    lastSeen: { type: DataTypes.DATE, defaultValue: DataTypes.NOW, field: 'last_seen' },
    profilePicture: { type: DataTypes.STRING(256), field: 'profile_picture' },
    isBanned: { type: DataTypes.BOOLEAN, defaultValue: false, field: 'is_banned' },
    emailVerified: { type: DataTypes.BOOLEAN, defaultValue: false, field: 'email_verified' },
    soundMessage: { type: DataTypes.STRING(256), field: 'sound_message' },
    soundCalling: { type: DataTypes.STRING(256), field: 'sound_calling' },
    activeTheme: { type: DataTypes.STRING(20), defaultValue: 'kryonix', field: 'active_theme' },
    customCssUrl: { type: DataTypes.STRING(256), field: 'custom_css_url' }
}, { tableName: 'users', timestamps: false });

// BannedEmail Model
const BannedEmail = sequelize.define('BannedEmail', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    email: { type: DataTypes.STRING(120), unique: true, allowNull: false }
}, { tableName: 'banned_emails', timestamps: false });

// Message Model
const Message = sequelize.define('Message', {
    id: { type: DataTypes.STRING(64), primaryKey: true },
    room: { type: DataTypes.STRING(200), allowNull: false, index: true },
    senderUsername: { type: DataTypes.STRING(80), allowNull: false, field: 'sender_username' },
    content: { type: DataTypes.TEXT, allowNull: false },
    timestamp: { type: DataTypes.DATE, defaultValue: DataTypes.NOW, index: true },
    timeDisplay: { type: DataTypes.STRING(10), field: 'time_display' },
    isDeleted: { type: DataTypes.BOOLEAN, defaultValue: false, field: 'is_deleted' },
    replyTo: { type: DataTypes.JSON, field: 'reply_to' }
}, { tableName: 'messages', timestamps: false });

// GroupChat Model
const GroupChat = sequelize.define('GroupChat', {
    id: { type: DataTypes.STRING(64), primaryKey: true },
    name: { type: DataTypes.STRING(100), allowNull: false },
    creator: { type: DataTypes.STRING(80), allowNull: false },
    createdAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW, field: 'created_at' }
}, { tableName: 'group_chats', timestamps: false });

// GroupMember Model
const GroupMember = sequelize.define('GroupMember', {
    groupId: { type: DataTypes.STRING(64), primaryKey: true, field: 'group_id' },
    username: { type: DataTypes.STRING(80), primaryKey: true }
}, { tableName: 'group_members', timestamps: false });

// Relationships
GroupChat.hasMany(GroupMember, { foreignKey: 'groupId', as: 'members' });
GroupMember.belongsTo(GroupChat, { foreignKey: 'groupId', as: 'group' });
GroupMember.belongsTo(User, { foreignKey: 'username', as: 'user' });
User.hasMany(GroupMember, { foreignKey: 'username', as: 'groupMemberships' });

// ── Middleware ─────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('static'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
    secret: SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    store: new SQLiteStore({ db: 'sessions.db', dir: '.' }),
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// CSRF token generation
function generateCsrfToken(req) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    return req.session.csrfToken;
}

app.use((req, res, next) => {
    res.locals.csrfToken = () => generateCsrfToken(req);
    res.locals.session = req.session || {};
    next();
});

// Auth middleware
function isAuthenticated(req, res, next) {
    if (req.session.username) return next();
    res.redirect('/login');
}

// ── Multer Setup ─────────────────────────────────────────────
const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, UPLOAD_FOLDER),
        filename: (req, file, cb) => cb(null, `${Date.now()}_${file.originalname}`)
    }),
    limits: { fileSize: MAX_CONTENT_LENGTH }
});

const profilePicUpload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, PROFILE_PICS_FOLDER),
        filename: (req, file, cb) => cb(null, `${req.session.username}_${Date.now()}_${file.originalname}`)
    }),
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase().slice(1);
        if (ALLOWED_IMAGE_EXTENSIONS.includes(ext)) cb(null, true);
        else cb(new Error('Invalid file type'));
    }
});

const soundUpload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, SOUNDS_FOLDER),
        filename: (req, file, cb) => cb(null, `${req.session.username}_${Date.now()}_${file.originalname}`)
    }),
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase().slice(1);
        if (ALLOWED_SOUND_EXTENSIONS.includes(ext)) cb(null, true);
        else cb(new Error('Invalid file type'));
    }
});

// ── Email Transporter ─────────────────────────────────────────────
const transporter = nodemailer.createTransport({
    host: MAIL_SERVER,
    port: MAIL_PORT,
    secure: false,
    auth: { user: MAIL_USERNAME, pass: MAIL_PASSWORD }
});

// ── Global State ─────────────────────────────────────────────
const userSids = {};
const activeCalls = {};
const activeGroupCalls = {};
const userMessageTimes = {};

// ── Helper Functions ─────────────────────────────────────────────
function allowedFile(filename, allowedSet) {
    const ext = filename.split('.').pop().toLowerCase();
    return allowedSet.includes(ext);
}

function checkRateLimit(username) {
    const now = Date.now() / 1000;
    if (!userMessageTimes[username]) userMessageTimes[username] = [];
    userMessageTimes[username] = userMessageTimes[username].filter(t => t > now - RATE_LIMIT_WINDOW);
    if (userMessageTimes[username].length >= RATE_LIMIT_MESSAGES) return false;
    userMessageTimes[username].push(now);
    return true;
}

function stripTags(text) {
    return text.replace(/<[^>]+>/g, '');
}

function generate2faCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function maskEmail(email) {
    if (!email || !email.includes('@')) return email;
    const [local, domain] = email.split('@');
    const visible = local.slice(0, 2);
    return `${visible}***@${domain}`;
}

function send2faEmail(recipient, code, subject = "Kryonix Verification Code") {
    const isLogin = subject.includes("Login");
    const headline = isLogin ? "Login Verification" : "Verify Your Email";
    const subLine = isLogin 
        ? "Use the code below to complete your login."
        : "You're almost in! Use the code below to verify your email address.";

    const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>${subject}</title></head>
<body style="margin:0;padding:0;background:#0d0d0d;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d0d0d;padding:40px 0;">
    <tr><td align="center">
      <table width="520" cellpadding="0" cellspacing="0" style="background:#181818;border-radius:16px;overflow:hidden;border:1px solid #2a2a2a;max-width:520px;width:100%;">
        <tr><td style="background:linear-gradient(135deg,#ff3f81,#c0226a);padding:32px 40px;text-align:center;">
          <p style="margin:0;font-size:28px;font-weight:800;color:#ffffff;letter-spacing:2px;text-transform:uppercase;">✦ KRYONIX</p>
          <p style="margin:8px 0 0;font-size:13px;color:rgba(255,255,255,0.75);letter-spacing:1px;text-transform:uppercase;">Secure Messaging</p>
        </td></tr>
        <tr><td style="padding:40px 40px 20px;text-align:center;">
          <h1 style="margin:0 0 12px;font-size:22px;font-weight:700;color:#ffffff;">${headline}</h1>
          <p style="margin:0 0 32px;font-size:15px;color:#aaaaaa;line-height:1.6;">${subLine}</p>
          <div style="background:#0d0d0d;border:1px solid #ff3f81;border-radius:12px;display:inline-block;padding:20px 48px;margin-bottom:32px;">
            <p style="margin:0;font-size:11px;letter-spacing:2px;color:#ff3f81;text-transform:uppercase;margin-bottom:8px;">Your code</p>
            <p style="margin:0;font-size:40px;font-weight:800;letter-spacing:10px;color:#ffffff;font-family:'Courier New',monospace;">${code}</p>
          </div>
          <p style="margin:0 0 8px;font-size:13px;color:#666;">⏱ This code expires in <strong style="color:#aaa;">10 minutes</strong>.</p>
          <p style="margin:0;font-size:13px;color:#555;">If you didn't request this, you can safely ignore this email.</p>
        </td></tr>
        <tr><td style="padding:0 40px;"><div style="height:1px;background:#2a2a2a;"></div></td></tr>
        <tr><td style="padding:20px 40px 32px;text-align:center;">
          <p style="margin:0;font-size:12px;color:#444;">© 2024 Kryonix. All rights reserved.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

    transporter.sendMail({
        from: MAIL_USERNAME,
        to: recipient,
        subject,
        html
    }).catch(err => console.error(`Failed to send email: ${err}`));
}

async function getUserModel(username) {
    return await User.findByPk(username);
}

async function getUserByLogin(loginField) {
    return await User.findOne({ where: { [Op.or]: [{ username: loginField }, { email: loginField }] } });
}

async function isEmailBanned(email) {
    const banned = await BannedEmail.findOne({ where: { email: email.toLowerCase() } });
    return !!banned;
}

async function updateUserStatus(username, status) {
    await User.update({ status, lastSeen: new Date() }, { where: { username } });
}

async function getRoomHistory(roomName, offset = 0, limit = MESSAGES_PER_PAGE) {
    const { count, rows } = await Message.findAndCountAll({
        where: { room: roomName },
        order: [['timestamp', 'ASC']],
        offset,
        limit
    });
    const messages = rows.map(m => ({
        id: m.id,
        username: m.senderUsername,
        msg: m.content,
        time: m.timeDisplay,
        room: m.room,
        reply_to: m.replyTo
    }));
    return { messages, total: count };
}

async function addMessageToDb(room, messageData) {
    try {
        await Message.create({
            id: messageData.id,
            room,
            senderUsername: messageData.username,
            content: messageData.msg,
            timeDisplay: messageData.time || '',
            replyTo: messageData.reply_to || null
        });
        return true;
    } catch (e) {
        console.error(`Error adding message: ${e}`);
        return false;
    }
}

async function updateMessageInDb(messageId, newText) {
    try {
        await Message.update({
            content: newText,
            isDeleted: newText === "<em>deleted message</em>"
        }, { where: { id: messageId } });
        return true;
    } catch (e) {
        console.error(`Error updating message: ${e}`);
        return false;
    }
}

async function deleteMessageInDb(messageId) {
    try {
        await Message.update({ content: "<em>deleted message</em>", isDeleted: true }, { where: { id: messageId } });
        return true;
    } catch (e) {
        console.error(`Error deleting message: ${e}`);
        return false;
    }
}

async function getGroupMembers(groupId) {
    const members = await GroupMember.findAll({ where: { groupId } });
    return members.map(m => m.username);
}

async function userInGroup(username, groupId) {
    const member = await GroupMember.findOne({ where: { groupId, username } });
    return !!member;
}

function loadThemeIntoSession(user, req) {
    const theme = user.activeTheme || 'kryonix';
    req.session.activeTheme = theme;
    
    if (theme === 'custom') {
        req.session.customCssUrl = user.customCssUrl || null;
    } else if (theme === 'dark') {
        req.session.customCssUrl = '/static/css/theme-dark.css';
    } else if (theme === 'light') {
        req.session.customCssUrl = '/static/css/theme-light.css';
    } else {
        req.session.customCssUrl = '/static/css/theme-kryonix.css';
    }
}

// ── Routes ─────────────────────────────────────────────

// Root redirect
app.get('/', (req, res) => {
    if (req.session.username) res.redirect('/chat');
    else res.redirect('/login');
});

// Register
app.get('/register', (req, res) => {
    if (req.session.username) return res.redirect('/chat');
    res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
    if (req.session.username) return res.redirect('/chat');
    
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.render('register', { error: 'All fields are required.' });
    }
    if (username.length < 3) {
        return res.render('register', { error: 'Username must be at least 3 characters.' });
    }
    if (!/^[\w.-]+$/.test(username)) {
        return res.render('register', { error: 'Username may only contain letters, numbers, dots, dashes, and underscores.' });
    }
    if (!email.includes('@') || !email.split('@')[1].includes('.')) {
        return res.render('register', { error: 'Invalid email format.' });
    }
    if (password.length < 6) {
        return res.render('register', { error: 'Password must be at least 6 characters.' });
    }
    
    const existingUser = await getUserModel(username);
    if (existingUser) {
        return res.render('register', { error: 'Username already taken.' });
    }
    
    const existingEmail = await User.findOne({ where: { email: email.toLowerCase() } });
    if (existingEmail) {
        return res.render('register', { error: 'Email already registered.' });
    }
    
    if (await isEmailBanned(email)) {
        return res.render('register', { error: 'This email address is banned from registration.' });
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    
    await User.create({
        username,
        email: email.toLowerCase(),
        passwordHash,
        friends: [],
        requests: [],
        blocked: [],
        settings: { primary_color: '#0f0f0f', accent_color: '#ff3f81' },
        status: 'offline',
        lastSeen: new Date(),
        emailVerified: false,
        activeTheme: 'kryonix'
    });
    
    const code = generate2faCode();
    req.session.verifyCode = code;
    req.session.verifyEmail = email.toLowerCase();
    req.session.verifyUsername = username;
    req.session.verifyCodeTime = Date.now();
    
    send2faEmail(email.toLowerCase(), code, "Kryonix — Verify Your Email");
    res.redirect('/verify-email');
});

// Login
app.get('/login', (req, res) => {
    if (req.session.username) return res.redirect('/chat');
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    if (req.session.username) return res.redirect('/chat');
    
    const { login_field, password } = req.body;
    
    const user = await getUserByLogin(login_field);
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        return res.render('login', { error: 'Invalid username/email or password.' });
    }
    
    if (await isEmailBanned(user.email)) {
        return res.render('login', { error: 'Your account is banned.' });
    }
    
    if (user.timeoutUntil && new Date(user.timeoutUntil) > new Date()) {
        return res.render('login', { error: `Account timed out until ${new Date(user.timeoutUntil).toLocaleString()}.` });
    }
    
    if (!user.emailVerified) {
        const code = generate2faCode();
        req.session.verifyCode = code;
        req.session.verifyEmail = user.email;
        req.session.verifyUsername = user.username;
        req.session.verifyCodeTime = Date.now();
        send2faEmail(user.email, code, "Kryonix — Verify Your Email");
        return res.render('login', { error: 'Email not verified. A new verification code has been sent to your email.' });
    }
    
    const code = generate2faCode();
    req.session.login2faCode = code;
    req.session.login2faUsername = user.username;
    req.session.login2faTime = Date.now();
    send2faEmail(user.email, code, "Kryonix — Login Verification Code");
    res.redirect('/verify-login');
});

// Logout
app.get('/logout', isAuthenticated, async (req, res) => {
    await updateUserStatus(req.session.username, 'offline');
    req.session.destroy();
    res.redirect('/login');
});

// Verify Email
app.get('/verify-email', async (req, res) => {
    if (req.session.username) return res.redirect('/chat');
    if (!req.session.verifyEmail) return res.redirect('/register');
    
    res.render('verify_email', {
        error: null,
        verified: false,
        masked_email: maskEmail(req.session.verifyEmail)
    });
});

app.post('/verify-email', async (req, res) => {
    const { code } = req.body;
    const stored = req.session.verifyCode;
    const issued = req.session.verifyCodeTime || 0;
    
    if (Date.now() / 1000 - issued > 600) {
        req.session.verifyCode = null;
        req.session.verifyEmail = null;
        req.session.verifyUsername = null;
        req.session.verifyCodeTime = null;
        return res.render('verify_email', { error: 'Code expired. Please register again.', verified: false, masked_email: '' });
    }
    
    if (code !== stored) {
        return res.render('verify_email', { error: 'Incorrect code. Please try again.', verified: false, masked_email: maskEmail(req.session.verifyEmail) });
    }
    
    const username = req.session.verifyUsername;
    req.session.verifyCode = null;
    req.session.verifyEmail = null;
    req.session.verifyUsername = null;
    req.session.verifyCodeTime = null;
    
    const user = await getUserModel(username);
    if (user) {
        user.emailVerified = true;
        await user.save();
    }
    
    res.render('verify_email', { verified: true });
});

app.get('/verify-email/resend', (req, res) => {
    if (!req.session.verifyEmail) return res.redirect('/register');
    const code = generate2faCode();
    req.session.verifyCode = code;
    req.session.verifyCodeTime = Date.now();
    send2faEmail(req.session.verifyEmail, code, "Kryonix — Verify Your Email");
    res.redirect('/verify-email');
});

// Verify Login
app.get('/verify-login', async (req, res) => {
    if (req.session.username) return res.redirect('/chat');
    if (!req.session.login2faUsername) return res.redirect('/login');
    
    const user = await getUserModel(req.session.login2faUsername);
    res.render('verify_login', {
        error: null,
        masked_email: user ? maskEmail(user.email) : ''
    });
});

app.post('/verify-login', async (req, res) => {
    const { code } = req.body;
    const stored = req.session.login2faCode;
    const issued = req.session.login2faTime || 0;
    
    if (Date.now() / 1000 - issued > 600) {
        req.session.login2faCode = null;
        req.session.login2faUsername = null;
        req.session.login2faTime = null;
        return res.redirect('/login');
    }
    
    if (code !== stored) {
        const user = await getUserModel(req.session.login2faUsername);
        return res.render('verify_login', { error: 'Incorrect code. Please try again.', masked_email: user ? maskEmail(user.email) : '' });
    }
    
    const username = req.session.login2faUsername;
    req.session.login2faCode = null;
    req.session.login2faTime = null;
    
    const user = await getUserModel(username);
    if (!user) return res.redirect('/login');
    
    req.session.username = username;
    req.session.email = user.email;
    await updateUserStatus(username, 'online');
    loadThemeIntoSession(user, req);
    
    res.redirect('/chat');
});

app.get('/verify-login/resend', async (req, res) => {
    const username = req.session.login2faUsername;
    if (!username) return res.redirect('/login');
    
    const user = await getUserModel(username);
    if (!user) return res.redirect('/login');
    
    const code = generate2faCode();
    req.session.login2faCode = code;
    req.session.login2faTime = Date.now();
    send2faEmail(user.email, code, "Kryonix — Login Verification Code");
    res.redirect('/verify-login');
});

// Chat
app.get('/chat', isAuthenticated, async (req, res) => {
    const user = await getUserModel(req.session.username);
    
    if (user.timeoutUntil && new Date(user.timeoutUntil) > new Date()) {
        req.session.destroy();
        return res.redirect('/login');
    }
    
    const friendsList = user.friends || [];
    
    const groupMemberships = await GroupMember.findAll({ where: { username: req.session.username } });
    const userGroups = [];
    for (const gm of groupMemberships) {
        const group = await GroupChat.findByPk(gm.groupId);
        if (group) {
            userGroups.push({
                id: group.id,
                name: group.name,
                members: await getGroupMembers(group.id)
            });
        }
    }
    
    req.session.primaryColor = (user.settings || {}).primary_color || '#0f0f0f';
    req.session.accentColor = (user.settings || {}).accent_color || '#ff3f81';
    loadThemeIntoSession(user, req);
    
    res.render('chat', {
        username: req.session.username,
        friends_list: friendsList,
        group_chats: userGroups,
        current_user: { username: req.session.username, profile_picture: user.profilePicture },
        max_message_length: MAX_MESSAGE_LENGTH
    });
});

// History
app.get('/history/:room_name', isAuthenticated, async (req, res) => {
    try {
        const offset = parseInt(req.query.offset) || 0;
        const limit = Math.min(parseInt(req.query.limit) || MESSAGES_PER_PAGE, 100);
        const roomName = req.params.room_name;
        
        if (roomName.startsWith('group_')) {
            const group = await GroupChat.findByPk(roomName);
            if (!group) return res.json({ error: 'Group not found' }).status(404);
            if (!(await userInGroup(req.session.username, roomName))) {
                return res.json({ error: 'You are not a member of this group' }).status(403);
            }
            const { messages, total } = await getRoomHistory(roomName, offset, limit);
            return res.json({ messages, total, has_more: (offset + messages.length) < total });
        }
        
        const parts = roomName.split('-');
        if (parts.length !== 2) return res.json({ error: 'Invalid room name' }).status(400);
        const [user1, user2] = parts;
        if (req.session.username !== user1 && req.session.username !== user2) {
            return res.json({ error: 'Unauthorized' }).status(403);
        }
        
        const user = await getUserModel(req.session.username);
        const target = req.session.username === user1 ? user2 : user1;
        if (!user.friends.includes(target)) {
            return res.json({ error: 'You are not friends with this user.' }).status(403);
        }
        
        const { messages, total } = await getRoomHistory(roomName, offset, limit);
        res.json({ messages, total, has_more: (offset + messages.length) < total });
    } catch (e) {
        console.error(`Error loading history: ${e}`);
        res.json({ error: 'Failed to load history' }).status(500);
    }
});

// File serving routes
app.get('/uploads/:filename', isAuthenticated, (req, res) => {
    const safe = path.basename(req.params.filename);
    res.sendFile(path.join(__dirname, UPLOAD_FOLDER, safe));
});

app.get('/profile_pics/:filename', (req, res) => {
    const safe = path.basename(req.params.filename);
    res.sendFile(path.join(__dirname, PROFILE_PICS_FOLDER, safe));
});

app.get('/custom_css/:filename', isAuthenticated, (req, res) => {
    const safe = path.basename(req.params.filename);
    res.sendFile(path.join(__dirname, CUSTOM_CSS_FOLDER, safe));
});

app.get('/custom_sounds/:filename', isAuthenticated, (req, res) => {
    const safe = path.basename(req.params.filename);
    res.sendFile(path.join(__dirname, SOUNDS_FOLDER, safe));
});

// Upload file
app.post('/upload_file', isAuthenticated, upload.single('file'), (req, res) => {
    try {
        if (!req.file) return res.json({ error: 'No file part' }).status(400);
        const url = `/uploads/${req.file.filename}`;
        res.json({ url });
    } catch (e) {
        console.error(`Error saving file: ${e}`);
        res.json({ error: 'Failed to save file' }).status(500);
    }
});

// Upload profile picture
app.post('/upload_profile_picture', isAuthenticated, profilePicUpload.single('file'), async (req, res) => {
    try {
        const user = await getUserModel(req.session.username);
        
        if (req.body.remove) {
            if (user.profilePicture) {
                const oldPath = path.join(PROFILE_PICS_FOLDER, path.basename(user.profilePicture));
                if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
                user.profilePicture = null;
                await user.save();
            }
            return res.json({ success: true });
        }
        
        if (!req.file) return res.json({ error: 'No file part' }).status(400);
        
        if (user.profilePicture) {
            const oldPath = path.join(PROFILE_PICS_FOLDER, path.basename(user.profilePicture));
            if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        }
        
        const fileUrl = `/profile_pics/${req.file.filename}`;
        user.profilePicture = fileUrl;
        await user.save();
        res.json({ url: fileUrl });
    } catch (e) {
        console.error(`Error uploading profile picture: ${e}`);
        res.json({ error: 'Failed to upload' }).status(500);
    }
});

// Get user sounds
app.get('/get_user_sounds', isAuthenticated, async (req, res) => {
    const user = await getUserModel(req.session.username);
    res.json({
        sound_message: user.soundMessage || null,
        sound_calling: user.soundCalling || null
    });
});

// Upload sound
app.post('/upload_sound/:sound_type', isAuthenticated, soundUpload.single('file'), async (req, res) => {
    const { sound_type } = req.params;
    if (!['message', 'calling'].includes(sound_type)) {
        return res.json({ error: 'Invalid sound type' }).status(400);
    }
    
    try {
        const user = await getUserModel(req.session.username);
        
        if (req.body.remove) {
            const col = `sound${sound_type.charAt(0).toUpperCase() + sound_type.slice(1)}`;
            const oldUrl = user[col];
            if (oldUrl) {
                const oldPath = path.join(SOUNDS_FOLDER, path.basename(oldUrl));
                if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
            }
            user[col] = null;
            await user.save();
            return res.json({ success: true });
        }
        
        if (!req.file) return res.json({ error: 'No file part' }).status(400);
        
        const col = `sound${sound_type.charAt(0).toUpperCase() + sound_type.slice(1)}`;
        const oldUrl = user[col];
        if (oldUrl) {
            const oldPath = path.join(SOUNDS_FOLDER, path.basename(oldUrl));
            if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        }
        
        const fileUrl = `/custom_sounds/${req.file.filename}`;
        user[col] = fileUrl;
        await user.save();
        res.json({ url: fileUrl });
    } catch (e) {
        console.error(`Error uploading sound: ${e}`);
        res.json({ error: 'Failed to upload' }).status(500);
    }
});

// Set theme
app.post('/settings/theme', isAuthenticated, async (req, res) => {
    try {
        const { theme } = req.body;
        if (!ALLOWED_THEMES.includes(theme)) {
            return res.json({ error: 'Invalid theme' }).status(400);
        }
        
        const user = await getUserModel(req.session.username);
        user.activeTheme = theme;
        await user.save();
        
        loadThemeIntoSession(user, req);
        res.json({ ok: true });
    } catch (e) {
        console.error(`Error setting theme: ${e}`);
        res.json({ error: 'Failed to save theme' }).status(500);
    }
});

// Upload custom CSS
app.post('/upload_custom_css', isAuthenticated, (req, res) => {
    try {
        const user = getUserModel(req.session.username);
        
        if (req.body.remove) {
            // Handle remove
            return res.json({ success: true });
        }
        
        if (!req.files || !req.files.file) {
            return res.json({ error: 'No file part' }).status(400);
        }
        
        const file = req.files.file;
        if (!file.name.endsWith('.css')) {
            return res.json({ error: 'Only .css files are allowed' }).status(400);
        }
        
        const uniqueFilename = `${req.session.username}_${Date.now()}_${file.name}`;
        const filePath = path.join(CUSTOM_CSS_FOLDER, uniqueFilename);
        
        file.mv(filePath, async (err) => {
            if (err) {
                console.error(`Error saving CSS: ${err}`);
                return res.json({ error: 'Failed to upload' }).status(500);
            }
            
            const cssUrl = `/custom_css/${uniqueFilename}`;
            const user = await getUserModel(req.session.username);
            user.customCssUrl = cssUrl;
            user.activeTheme = 'custom';
            await user.save();
            loadThemeIntoSession(user, req);
            res.json({ url: cssUrl });
        });
    } catch (e) {
        console.error(`Error uploading custom CSS: ${e}`);
        res.json({ error: 'Failed to upload' }).status(500);
    }
});

// Create group
app.post('/create_group', isAuthenticated, async (req, res) => {
    try {
        const { name, members } = req.body;
        if (!name || name.length > 50) {
            return res.json({ error: 'Invalid group name' }).status(400);
        }
        if (!members || members.length < 1) {
            return res.json({ error: 'At least 1 other member is required' }).status(400);
        }
        
        const user = await getUserModel(req.session.username);
        for (const member of members) {
            if (!user.friends.includes(member)) {
                return res.json({ error: `${member} is not your friend` }).status(400);
            }
        }
        
        const groupId = `group_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
        await GroupChat.create({ id: groupId, name, creator: req.session.username });
        await GroupMember.create({ groupId, username: req.session.username });
        for (const member of members) {
            await GroupMember.create({ groupId, username: member });
        }
        
        res.json({ success: true, group_id: groupId, group_name: name });
    } catch (e) {
        console.error(`Error creating group: ${e}`);
        res.json({ error: 'Failed to create group' }).status(500);
    }
});

// Create group (new endpoint for modal form)
app.post('/groups', isAuthenticated, async (req, res) => {
    try {
        const { name, members } = req.body;
        if (!name || name.trim().length === 0 || name.length > 50) {
            return res.json({ error: 'Invalid group name' }).status(400);
        }
        if (!members || members.length < 1) {
            return res.json({ error: 'At least 1 other member is required' }).status(400);
        }
        
        const user = await getUserModel(req.session.username);
        for (const member of members) {
            if (!user.friends.includes(member)) {
                return res.json({ error: `${member} is not your friend` }).status(400);
            }
        }
        
        const groupId = `group_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
        await GroupChat.create({ id: groupId, name: name.trim(), creator: req.session.username });
        await GroupMember.create({ groupId, username: req.session.username });
        for (const member of members) {
            await GroupMember.create({ groupId, username: member });
        }
        
        res.json({ success: true, group_id: groupId, group_name: name.trim() });
    } catch (e) {
        console.error(`Error creating group: ${e}`);
        res.json({ error: 'Failed to create group' }).status(500);
    }
});

// Get group info
app.get('/get_group_info/:group_id', isAuthenticated, async (req, res) => {
    try {
        const group = await GroupChat.findByPk(req.params.group_id);
        if (!group) return res.json({ error: 'Group not found' }).status(404);
        if (!(await userInGroup(req.session.username, req.params.group_id))) {
            return res.json({ error: 'You are not a member of this group' }).status(403);
        }
        
        const members = await getGroupMembers(req.params.group_id);
        const membersInfo = [];
        for (const username of members) {
            const u = await getUserModel(username);
            if (u) membersInfo.push({ username, profile_picture: u.profilePicture });
        }
        
        res.json({
            name: group.name,
            creator: group.creator,
            members: membersInfo,
            is_creator: req.session.username === group.creator
        });
    } catch (e) {
        console.error(`Error getting group info: ${e}`);
        res.json({ error: 'Failed to get group info' }).status(500);
    }
});

// Update group
app.post('/update_group/:group_id', isAuthenticated, async (req, res) => {
    try {
        const { action, name, member, members } = req.body;
        const groupId = req.params.group_id;
        
        const group = await GroupChat.findByPk(groupId);
        if (!group) return res.json({ error: 'Group not found' }).status(404);
        if (!(await userInGroup(req.session.username, groupId))) {
            return res.json({ error: 'You are not a member of this group' }).status(403);
        }
        
        if (action === 'rename') {
            if (req.session.username !== group.creator) {
                return res.json({ error: 'Only the creator can rename the group' }).status(403);
            }
            if (!name || name.length > 50) {
                return res.json({ error: 'Invalid group name' }).status(400);
            }
            group.name = name;
            await group.save();
            return res.json({ success: true });
        }
        
        if (action === 'kick') {
            if (req.session.username !== group.creator) {
                return res.json({ error: 'Only the creator can kick members' }).status(403);
            }
            if (member === group.creator) {
                return res.json({ error: 'Cannot kick the creator' }).status(400);
            }
            await GroupMember.destroy({ where: { groupId, username: member } });
            return res.json({ success: true });
        }
        
        if (action === 'leave') {
            if (req.session.username === group.creator) {
                return res.json({ error: 'Creators cannot leave — delete the group instead' }).status(400);
            }
            await GroupMember.destroy({ where: { groupId, username: req.session.username } });
            return res.json({ success: true });
        }
        
        if (action === 'add_members') {
            if (req.session.username !== group.creator) {
                return res.json({ error: 'Only the creator can add members' }).status(403);
            }
            const user = await getUserModel(req.session.username);
            for (const m of members) {
                if (!user.friends.includes(m)) continue;
                if (!(await userInGroup(m, groupId))) {
                    await GroupMember.create({ groupId, username: m });
                }
            }
            return res.json({ success: true });
        }
        
        res.json({ error: 'Invalid action' }).status(400);
    } catch (e) {
        console.error(`Error updating group: ${e}`);
        res.json({ error: 'Failed to update group' }).status(500);
    }
});

// Groups page
app.get('/groups', isAuthenticated, async (req, res) => {
    const user = await getUserModel(req.session.username);
    const groupMemberships = await GroupMember.findAll({ where: { username: req.session.username } });
    const userGroups = [];
    for (const gm of groupMemberships) {
        const group = await GroupChat.findByPk(gm.groupId);
        if (group) {
            userGroups.push({
                id: group.id,
                name: group.name,
                creator: group.creator,
                members: await getGroupMembers(group.id),
                created_at: group.createdAt.toISOString()
            });
        }
    }
    
    res.render('groups', {
        current_user: { username: req.session.username },
        user_groups: userGroups,
        friends_list: user.friends || [],
        message: null,
        message_type: null
    });
});

// Friends page
app.get('/friends', isAuthenticated, async (req, res) => {
    const user = await getUserModel(req.session.username);
    res.render('friends', {
        current_user: { username: req.session.username },
        user_data: {
            friends: user.friends || [],
            requests: user.requests || [],
            blocked: user.blocked || []
        },
        message: null,
        message_type: null
    });
});

app.post('/friends', isAuthenticated, async (req, res) => {
    const { action, target_username } = req.body;
    let message = null, message_type = null;
    
    const user = await getUserModel(req.session.username);
    const target = await getUserModel(target_username);
    
    if (!target_username) {
        message = "Target username is required.";
        message_type = "error";
    } else if (target_username === req.session.username) {
        message = "You cannot perform this action on yourself.";
        message_type = "error";
    } else if (!target) {
        message = `User '${target_username}' not found.`;
        message_type = "error";
    } else {
        try {
            if (action === 'send_request') {
                if (user.friends.includes(target_username) || user.requests.includes(target_username) || target.requests.includes(req.session.username)) {
                    message = "Request already pending or already friends.";
                    message_type = "error";
                } else if (user.blocked.includes(target_username)) {
                    message = `You have blocked '${target_username}'.`;
                    message_type = "error";
                } else if (target.blocked.includes(req.session.username)) {
                    message = `You are blocked by '${target_username}'.`;
                    message_type = "error";
                } else {
                    target.requests = [...(target.requests || []), req.session.username];
                    await target.save();
                    message = `Friend request sent to '${target_username}'.`;
                    message_type = "success";
                }
            } else if (action === 'accept_request') {
                // Accept logic: Add to friends list for both users and remove request
                if (!user.friends.includes(target_username)) {
                    user.friends = [...(user.friends || []), target_username];
                }
                if (!target.friends.includes(req.session.username)) {
                    target.friends = [...(target.friends || []), req.session.username];
                }
                user.requests = (user.requests || []).filter(r => r !== target_username);
                await user.save();
                await target.save();
                message = `Accepted friend request from '${target_username}'.`;
                message_type = "success";
            } else if (action === 'decline_request') {
                user.requests = (user.requests || []).filter(r => r !== target_username);
                await user.save();
                message = `Declined friend request from '${target_username}'.`;
                message_type = "success";
            } else if (action === 'remove_friend') {
                user.friends = (user.friends || []).filter(f => f !== target_username);
                target.friends = (target.friends || []).filter(f => f !== req.session.username);
                await user.save();
                await target.save();
                message = `Removed '${target_username}' from friends.`;
                message_type = "success";
            } else if (action === 'block_user') {
                user.blocked = [...(user.blocked || []), target_username];
                user.friends = (user.friends || []).filter(f => f !== target_username);
                user.requests = (user.requests || []).filter(r => r !== target_username);
                await user.save();
                message = `Blocked '${target_username}'.`;
                message_type = "success";
            } else if (action === 'unblock_user') {
                user.blocked = (user.blocked || []).filter(b => b !== target_username);
                await user.save();
                message = `Unblocked '${target_username}'.`;
                message_type = "success";
            } else {
                message = "Invalid action.";
                message_type = "error";
            }
        } catch (e) {
            message = `An error occurred: ${e}`;
            message_type = "error";
        }
    }
    
    const updatedUser = await getUserModel(req.session.username);
    res.render('friends', {
        current_user: { username: req.session.username },
        user_data: {
            friends: updatedUser.friends || [],
            requests: updatedUser.requests || [],
            blocked: updatedUser.blocked || []
        },
        message,
        message_type
    });
});

// Settings page
app.get('/settings', isAuthenticated, async (req, res) => {
    const user = await getUserModel(req.session.username);
    loadThemeIntoSession(user, req);
    
    res.render('settings', {
        current_user: { username: req.session.username },
        settings: user.settings || {},
        user_data: {
            email: user.email,
            username: user.username,
            profile_picture: user.profilePicture,
            sound_message: user.soundMessage,
            sound_calling: user.soundCalling,
            active_theme: user.activeTheme || 'kryonix',
            custom_css_url: user.customCssUrl
        },
        message: null,
        message_type: null
    });
});

app.post('/settings', isAuthenticated, async (req, res) => {
    const { section, primary_color, accent_color, username: newUsername, email: newEmail, current_password, new_password, active_theme } = req.body;
    let message = null, message_type = null;
    
    const user = await getUserModel(req.session.username);
    
    if (section === 'theme' || active_theme) {
        // Handle theme change
        if (active_theme && ALLOWED_THEMES.includes(active_theme)) {
            user.activeTheme = active_theme;
            await user.save();
            loadThemeIntoSession(user, req);
            message = `Theme changed to ${active_theme}!`;
            message_type = "success";
        } else if (primary_color && accent_color) {
            if (!/^#[0-9a-fA-F]{6}$/.test(primary_color) || !/^#[0-9a-fA-F]{6}$/.test(accent_color)) {
                message = "Invalid colour format.";
                message_type = "error";
            } else {
                user.settings = { ...(user.settings || {}), primary_color, accent_color };
                await user.save();
                req.session.primaryColor = primary_color;
                req.session.accentColor = accent_color;
                message = "Theme settings updated successfully!";
                message_type = "success";
            }
        }
    } else if (section === 'account') {
        if (newUsername && newUsername !== req.session.username) {
            // Username change logic
            message = "Username changed successfully! Please log in again.";
            message_type = "success";
        }
        if (newEmail && newEmail !== user.email) {
            user.email = newEmail.toLowerCase();
            await user.save();
            message = "Email updated successfully!";
            message_type = "success";
        }
        if (current_password && new_password) {
            const valid = await bcrypt.compare(current_password, user.passwordHash);
            if (!valid) {
                message = "Current password is incorrect.";
                message_type = "error";
            } else if (new_password.length < 6) {
                message = "New password must be at least 6 characters.";
                message_type = "error";
            } else {
                user.passwordHash = await bcrypt.hash(new_password, 10);
                await user.save();
                message = "Password changed successfully!";
                message_type = "success";
            }
        }
    }
    
    const updatedUser = await getUserModel(req.session.username);
    loadThemeIntoSession(updatedUser, req);
    
    res.render('settings', {
        current_user: { username: req.session.username },
        settings: updatedUser.settings || {},
        user_data: {
            email: updatedUser.email,
            username: updatedUser.username,
            profile_picture: updatedUser.profilePicture,
            sound_message: updatedUser.soundMessage,
            sound_calling: updatedUser.soundCalling,
            active_theme: updatedUser.activeTheme || 'kryonix',
            custom_css_url: updatedUser.customCssUrl
        },
        message,
        message_type
    });
});

// Admin page
app.get('/admin', isAuthenticated, async (req, res) => {
    if (req.session.username !== 'admin') return res.status(403).send('Forbidden');
    
    const users = await User.findAll({ where: { username: { [Op.ne]: 'admin' } } });
    const banned = await BannedEmail.findAll();
    
    res.render('admin', {
        current_user: { username: req.session.username },
        users,
        banned_list: banned.map(b => b.email),
        message: null,
        message_type: null
    });
});

// Get pending requests count
app.get('/get_pending_requests_count', isAuthenticated, async (req, res) => {
    const user = await getUserModel(req.session.username);
    res.json({ count: (user.requests || []).length });
});

// Get user profiles
app.post('/get_user_profiles', isAuthenticated, async (req, res) => {
    const { usernames } = req.body;
    const profiles = {};
    for (const username of usernames) {
        const user = await getUserModel(username);
        if (user) profiles[username] = { profile_picture: user.profilePicture };
    }
    res.json(profiles);
});

// Get contacts order
app.get('/get_contacts_order', isAuthenticated, async (req, res) => {
    try {
        const user = await getUserModel(req.session.username);
        const contacts = [];
        
        for (const friend of user.friends || []) {
            const roomName = [req.session.username, friend].sort().join('-');
            const lastMsg = await Message.findOne({ where: { room: roomName }, order: [['timestamp', 'DESC']] });
            contacts.push({
                id: friend,
                type: 'direct',
                last_message_time: lastMsg?.timestamp.toISOString() || null,
                last_message_timestamp: lastMsg ? Date.parse(lastMsg.timestamp) : 0,
                last_message_text: lastMsg?.content || '',
                unread_count: 0
            });
        }
        
        const groupMemberships = await GroupMember.findAll({ where: { username: req.session.username } });
        for (const gm of groupMemberships) {
            const group = await GroupChat.findByPk(gm.groupId);
            if (group) {
                const lastMsg = await Message.findOne({ where: { room: group.id }, order: [['timestamp', 'DESC']] });
                contacts.push({
                    id: group.id,
                    type: 'group',
                    name: group.name,
                    last_message_time: lastMsg?.timestamp.toISOString() || null,
                    last_message_timestamp: lastMsg ? Date.parse(lastMsg.timestamp) : 0,
                    last_message_text: lastMsg?.content || '',
                    unread_count: 0
                });
            }
        }
        
        contacts.sort((a, b) => (b.last_message_timestamp || 0) - (a.last_message_timestamp || 0));
        res.json({ contacts });
    } catch (e) {
        console.error(`Error getting contacts order: ${e}`);
        res.json({ error: 'Failed to get contacts order' }).status(500);
    }
});

// ── Socket.IO Events ─────────────────────────────────────────────
io.use((socket, next) => {
    // Simple session check for socket.io
    next();
});

io.on('connection', (socket) => {
    socket.on('connect', async () => {
        // Handle connection
    });
    
    socket.on('disconnect', async () => {
        // Handle disconnect
    });
    
    socket.on('user_connected', async (data) => {
        // Handle user connected
    });
    
    socket.on('request_statuses', () => {
        // Request all user statuses
    });
    
    socket.on('join', async (data) => {
        // Join room
    });
    
    socket.on('leave', (data) => {
        // Leave room
    });
    
    socket.on('send_message', async (data) => {
        // Send message
    });
    
    socket.on('edit_message', async (data) => {
        // Edit message
    });
    
    socket.on('delete_message', async (data) => {
        // Delete message
    });
    
    socket.on('typing_start', (data) => {
        // Typing indicator
    });
    
    socket.on('typing_stop', (data) => {
        // Stop typing
    });
    
    socket.on('call_user', async (data) => {
        // Call user
    });
    
    socket.on('answer_call', (data) => {
        // Answer call
    });
    
    socket.on('reject_call', (data) => {
        // Reject call
    });
    
    socket.on('end_call', async (data) => {
        // End call
    });
    
    socket.on('webrtc_offer', (data) => {
        // WebRTC offer
    });
    
    socket.on('webrtc_answer', (data) => {
        // WebRTC answer
    });
    
    socket.on('webrtc_ice_candidate', (data) => {
        // ICE candidate
    });
    
    socket.on('group_call_start', async (data) => {
        // Group call start
    });
    
    socket.on('group_call_leave', (data) => {
        // Group call leave
    });
    
    socket.on('group_call_reject', (data) => {
        // Group call reject
    });
    
    socket.on('group_webrtc_offer', (data) => {
        // Group WebRTC offer
    });
    
    socket.on('group_webrtc_answer', (data) => {
        // Group WebRTC answer
    });
    
    socket.on('group_webrtc_ice', (data) => {
        // Group ICE candidate
    });
});

// ── Startup ─────────────────────────────────────────────
async function initializeDatabase() {
    await sequelize.sync();
    
    const admin = await getUserModel('admin');
    if (!admin) {
        const passwordHash = await bcrypt.hash('admin', 10);
        await User.create({
            username: 'admin',
            email: 'thomas.desmidt1@gmail.com',
            passwordHash,
            friends: [],
            requests: [],
            blocked: [],
            settings: { primary_color: '#ff3f81', accent_color: '#0f0f0f' },
            status: 'offline',
            lastSeen: new Date(),
            emailVerified: true,
            activeTheme: 'kryonix'
        });
        console.log("Admin user created. Username: admin / Password: admin");
        console.log("!!! IMPORTANT: Change admin password immediately !!!");
    }
}

initializeDatabase().then(() => {
    server.listen(PORT, '0.0.0.0', () => {
        console.log(`Kryonix Chat running on http://localhost:${PORT}`);
    });
});
