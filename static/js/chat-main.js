// ── Kryonix Chat — chat-main.js ──────────────────────────────────────────────
// Exports: window.socket, window.username, window.currentRoom,
//          window.currentGroupRoom, window.showOverlay, window.hideOverlay

// ── Socket + globals ──────────────────────────────────────────────────────────
const socket = io({
    reconnection:       true,
    reconnectionDelay:  1500,
    reconnectionAttempts: Infinity,
    timeout:            10000,
});
window.socket = socket;
window.username = document.querySelector('.username').textContent.trim();
const username = window.username;

const MAX_MESSAGE_LENGTH = parseInt(document.getElementById('message-input').maxLength);

// ── State ─────────────────────────────────────────────────────────────────────
let currentRoom     = null;
let currentRoomType = 'direct';
let isLoadingHistory = false;
let typingTimeout   = null;
let replyingTo      = null;
let messageOffset   = 0;
let hasMoreMessages = true;
let isLoadingMore   = false;
let pendingMediaFile = null;
let userProfiles    = {};
let userScrolledUp  = false;
let isAtBottom      = true;
let pendingRequestCount = 0;  // friend-request badge

// ── DOM ───────────────────────────────────────────────────────────────────────
const sidebar            = document.getElementById('sidebar');
const menuToggle         = document.getElementById('menu-toggle');
const closeSidebarButton = document.getElementById('close-sidebar-button');
const chatMessagesDiv    = document.getElementById('chat-messages');
const messageInput       = document.getElementById('message-input');
const sendButton         = document.getElementById('send-button');
const currentChatHeader  = document.getElementById('current-chat-header');
const mobileChatTitle    = document.getElementById('mobile-chat-title');
const friendListUl       = document.getElementById('friend-list-ul');
const fileInput          = document.getElementById('file-input');
const statusOverlay      = document.getElementById('status-overlay');
const overlayMessage     = document.getElementById('overlay-message');
const selectChatPrompt   = document.getElementById('select-chat-prompt');
const contactSearch      = document.getElementById('contact-search');
const charCounter        = document.getElementById('char-counter');
const notificationSound  = document.getElementById('notification-sound');
const callIcons          = document.getElementById('call-icons');
const groupCallIcons     = document.getElementById('group-call-icons');
const editGroupBtn       = document.getElementById('edit-group-btn');

// Group modal
const createGroupBtn     = document.getElementById('create-group-btn');
const groupModal         = document.getElementById('group-modal');
const groupModalTitle    = document.getElementById('group-modal-title');
const createGroupForm    = document.getElementById('create-group-form');
const editGroupForm      = document.getElementById('edit-group-form');
const cancelGroupBtn     = document.getElementById('cancel-group-btn');
const cancelEditGroupBtn = document.getElementById('cancel-edit-group-btn');
const createGroupSubmit  = document.getElementById('create-group-submit');
const groupNameInput     = document.getElementById('group-name-input');
const editGroupNameInput = document.getElementById('edit-group-name-input');
const saveGroupBtn       = document.getElementById('save-group-btn');
const leaveGroupBtn      = document.getElementById('leave-group-btn');
const groupMembersList   = document.getElementById('group-members-list');
const showAddMembersBtn  = document.getElementById('show-add-members-btn');
const addMembersSection  = document.getElementById('add-members-section');
const addMemberSelection = document.getElementById('add-member-selection');
const confirmAddMembers  = document.getElementById('confirm-add-members');

// Reply
const replyPreview  = document.getElementById('reply-preview');
const replyUsername = document.getElementById('reply-username');
const replyText     = document.getElementById('reply-text');
const cancelReplyBtn= document.getElementById('cancel-reply');

// Media preview
const mediaPreviewModal     = document.getElementById('media-preview-modal');
const mediaPreviewContainer = document.getElementById('media-preview-container');
const sendMediaBtn          = document.getElementById('send-media-btn');
const cancelMediaBtn        = document.getElementById('cancel-media-btn');

// ── Page visibility ───────────────────────────────────────────────────────────
let isPageVisible = !document.hidden;
let isPageFocused = document.hasFocus();

document.addEventListener('visibilitychange', () => {
    isPageVisible = !document.hidden;
    if (isPageVisible) clearTitleBadge();
});
window.addEventListener('focus', () => { isPageFocused = true; clearTitleBadge(); });
window.addEventListener('blur',  () => { isPageFocused = false; });

function clearTitleBadge() {
    document.title = document.title.replace(/^\(\d+\)\s*/, '').replace(/^\(New message\)\s*/, '');
}

// ── Overlay (exported for webrtc modules) ─────────────────────────────────────
function showOverlay(msg) {
    if (!statusOverlay || !overlayMessage) return;
    overlayMessage.textContent = msg;
    statusOverlay.classList.add('active');
}
function hideOverlay() {
    if (statusOverlay) statusOverlay.classList.remove('active');
}
window.showOverlay = showOverlay;
window.hideOverlay = hideOverlay;

// ── Connection state indicator (subtle — no disruptive overlay) ───────────────
let connBanner = null;

function showConnBanner(msg) {
    if (!connBanner) {
        connBanner = document.createElement('div');
        connBanner.id = 'conn-banner';
        connBanner.style.cssText = [
            'position:fixed', 'top:0', 'left:0', 'right:0',
            'background:rgba(0,0,0,0.75)', 'color:#fff',
            'text-align:center', 'padding:6px 12px',
            'font-size:.85rem', 'z-index:9000',
            'backdrop-filter:blur(4px)',
            'transition:opacity .3s',
        ].join(';');
        document.body.appendChild(connBanner);
    }
    connBanner.textContent = msg;
    connBanner.style.display = 'block';
    connBanner.style.opacity = '1';
}

function hideConnBanner() {
    if (!connBanner) return;
    connBanner.style.opacity = '0';
    setTimeout(() => { if (connBanner) connBanner.style.display = 'none'; }, 350);
}

// ── Reconnect after navigating back to an active room ────────────────────────
function rejoinRoom() {
    if (currentRoom) {
        socket.emit('join', { room: currentRoom });
        loadChatHistory(currentRoom);
    }
}

// ── Socket — connection lifecycle ─────────────────────────────────────────────
socket.on('connect', () => {
    hideConnBanner();
    socket.emit('user_connected');
    socket.emit('request_statuses');

    // Reload profiles and contact order
    const friendUsernames = Array.from(friendListUl.querySelectorAll('li[data-friend-username]'))
        .map(li => li.dataset.friendUsername);
    if (friendUsernames.length) loadUserProfiles(friendUsernames);
    loadContactsWithTimestamps();

    // Re-join the active room if the page was already showing a chat
    rejoinRoom();

    // Restore from localStorage on first connect
    if (!currentRoom) {
        const storedType = localStorage.getItem('activeRoomType');
        if (storedType === 'group') {
            const storedRoom = localStorage.getItem('activeRoom');
            if (storedRoom) {
                const li = friendListUl.querySelector(`li[data-room-id="${storedRoom}"]`);
                if (li) selectRoom(storedRoom, 'group', li.dataset.roomName, li);
            }
        } else {
            const storedFriend = localStorage.getItem('activeFriend');
            if (storedFriend) selectFriend(storedFriend);
        }
    }
});

socket.on('disconnect', (reason) => {
    // Never show a disruptive modal — just a quiet top banner
    showConnBanner('Reconnecting…');
});

socket.on('reconnect', () => {
    hideConnBanner();
    socket.emit('user_connected');
    socket.emit('request_statuses');
    loadContactsWithTimestamps();
    rejoinRoom();
});

socket.on('reconnect_attempt', (n) => {
    showConnBanner(`Reconnecting… (attempt ${n})`);
});

socket.on('reconnect_failed', () => {
    showConnBanner('Connection lost. Please refresh the page.');
});

// ── Notification helpers ──────────────────────────────────────────────────────
if (Notification.permission !== 'granted' && Notification.permission !== 'denied') {
    Notification.requestPermission();
}

function notify(title, body, tag) {
    if (isPageFocused && isPageVisible) return;

    if (Notification.permission === 'granted') {
        const n = new Notification(title, { body, tag, icon: '/static/favicon.ico' });
        n.onclick = () => { window.focus(); n.close(); };
    }

    if (notificationSound) {
        notificationSound.currentTime = 0;
        notificationSound.play().catch(() => {});
    }

    if (!document.title.includes('New message')) {
        document.title = `(New message) ${clearTitleBadge() || document.title}`;
    }
}

// ── Utility ───────────────────────────────────────────────────────────────────
function stripHtml(html) {
    const d = document.createElement('div');
    d.innerHTML = html;
    return d.textContent || '';
}

function scrollToBottom(force = false) {
    if (force || !userScrolledUp) {
        setTimeout(() => { chatMessagesDiv.scrollTop = chatMessagesDiv.scrollHeight; }, 60);
    }
}

function scrollToMessage(id) {
    const el = chatMessagesDiv.querySelector(`[data-message-id="${id}"]`);
    if (!el) return;
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.classList.add('highlighted');
    setTimeout(() => el.classList.remove('highlighted'), 1200);
}

// ── Friend-request badge ──────────────────────────────────────────────────────
function refreshFriendRequestBadge(count) {
    pendingRequestCount = count;
    const navLinks = document.querySelectorAll('nav a');
    navLinks.forEach(a => {
        if (a.href.includes('/friends')) {
            let badge = a.querySelector('.fr-badge');
            if (count > 0) {
                if (!badge) {
                    badge = document.createElement('span');
                    badge.className = 'fr-badge';
                    badge.style.cssText = [
                        'background:var(--danger)', 'color:#fff',
                        'font-size:.7rem', 'font-weight:700',
                        'padding:1px 6px', 'border-radius:10px',
                        'margin-left:6px', 'vertical-align:middle',
                    ].join(';');
                    a.appendChild(badge);
                }
                badge.textContent = count;
            } else {
                if (badge) badge.remove();
            }
        }
    });
}

// Poll friend-request count every 30 s (lightweight GET, no socket needed)
async function pollFriendRequests() {
    try {
        const r = await fetch('/get_pending_requests_count');
        if (r.ok) {
            const d = await r.json();
            refreshFriendRequestBadge(d.count || 0);
        }
    } catch (_) {}
}

// ── Real-time socket events for social updates ────────────────────────────────
socket.on('friend_request_received', (data) => {
    refreshFriendRequestBadge(data.pending_count);
    notify('Friend Request', `${data.from} sent you a friend request`, 'fr-' + data.from);
});

socket.on('friend_request_accepted', (data) => {
    // Add the new friend to the sidebar without a page reload
    addFriendToSidebar(data.username, data.profile_picture);
    notify('New Friend', `${data.username} accepted your friend request`, 'fa-' + data.username);
});

socket.on('friend_removed', (data) => {
    // Remove from sidebar in real-time
    const li = friendListUl.querySelector(`li[data-friend-username="${data.username}"]`);
    if (li) li.remove();
    // If we were chatting with this person, close the chat
    const room = [username, data.username].sort().join('-');
    if (currentRoom === room) {
        currentRoom = null;
        window.currentRoom = null;
        chatMessagesDiv.innerHTML = '';
        currentChatHeader.textContent = '';
        if (callIcons) callIcons.style.display = 'none';
        if (selectChatPrompt) selectChatPrompt.style.display = 'block';
    }
});

socket.on('group_membership_update', (data) => {
    if (data.action === 'added') {
        // New group we were added to
        addGroupToSidebar(data.group_id, data.group_name);
    } else if (data.action === 'removed') {
        const li = friendListUl.querySelector(`li[data-room-id="${data.group_id}"]`);
        if (li) li.remove();
        if (currentRoom === data.group_id) {
            currentRoom = null;
            window.currentRoom = null;
            chatMessagesDiv.innerHTML = '';
            currentChatHeader.textContent = '';
            if (selectChatPrompt) selectChatPrompt.style.display = 'block';
        }
    } else if (data.action === 'renamed') {
        const li = friendListUl.querySelector(`li[data-room-id="${data.group_id}"]`);
        if (li) {
            li.dataset.roomName = data.group_name;
            const span = li.querySelector('.contact-name span');
            if (span) span.innerHTML = `${data.group_name} <span class="group-indicator">GROUP</span>`;
            if (currentRoom === data.group_id) currentChatHeader.textContent = data.group_name;
        }
    }
});

function addFriendToSidebar(friendName, profilePic) {
    if (friendListUl.querySelector(`li[data-friend-username="${friendName}"]`)) return;
    const li = document.createElement('li');
    li.dataset.friendUsername = friendName;
    li.dataset.roomType = 'direct';
    li.innerHTML = `
        <div class="contact-info">
            <div class="friend-avatar">
                <span id="avatar-${friendName}">${friendName[0].toUpperCase()}</span>
                <span class="status-indicator offline" data-username="${friendName}"></span>
            </div>
            <div class="contact-details">
                <div class="contact-name"><span>${friendName}</span></div>
                <div class="last-message-preview" data-contact-id="${friendName}"></div>
            </div>
        </div>`;
    friendListUl.appendChild(li);
    if (profilePic) {
        const av = li.querySelector(`#avatar-${friendName}`);
        if (av) av.innerHTML = `<img src="${profilePic}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">`;
    }
    // Remove the "no friends" placeholder if present
    const placeholder = friendListUl.querySelector('.initial-chat-message');
    if (placeholder) placeholder.remove();
}

function addGroupToSidebar(groupId, groupName) {
    if (friendListUl.querySelector(`li[data-room-id="${groupId}"]`)) return;
    const li = document.createElement('li');
    li.dataset.roomId   = groupId;
    li.dataset.roomType = 'group';
    li.dataset.roomName = groupName;
    li.innerHTML = `
        <div class="contact-info">
            <div class="friend-avatar" style="background:var(--primary);">
                <i class="fas fa-users"></i>
            </div>
            <div class="contact-details">
                <div class="contact-name">
                    <span>${groupName} <span class="group-indicator">GROUP</span></span>
                </div>
                <div class="last-message-preview" data-contact-id="${groupId}"></div>
            </div>
        </div>`;
    friendListUl.prepend(li);
    const placeholder = friendListUl.querySelector('.initial-chat-message');
    if (placeholder) placeholder.remove();
}

// ── Sidebar / mobile ──────────────────────────────────────────────────────────
menuToggle.addEventListener('click', () => sidebar.classList.add('active'));
closeSidebarButton.addEventListener('click', () => sidebar.classList.remove('active'));

// ── Contact search ────────────────────────────────────────────────────────────
contactSearch.addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    friendListUl.querySelectorAll('li[data-friend-username], li[data-room-id]').forEach(li => {
        const nameEl = li.querySelector('.contact-name span') || li.querySelector('span');
        const name = nameEl ? nameEl.textContent.toLowerCase() : '';
        li.style.display = name.includes(q) ? '' : 'none';
    });
});

// ── Char counter + typing ─────────────────────────────────────────────────────
messageInput.addEventListener('input', () => {
    const len = messageInput.value.length;
    charCounter.textContent = `${len} / ${MAX_MESSAGE_LENGTH}`;
    charCounter.classList.toggle('visible', len > 0);
    charCounter.classList.toggle('warning', len > MAX_MESSAGE_LENGTH * 0.9 && len < MAX_MESSAGE_LENGTH);
    charCounter.classList.toggle('error',   len >= MAX_MESSAGE_LENGTH);

    if (currentRoom) {
        socket.emit('typing_start', { room: currentRoom });
        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(() => socket.emit('typing_stop', { room: currentRoom }), 1200);
    }
});

// ── Infinite scroll (load older messages) ────────────────────────────────────
chatMessagesDiv.addEventListener('scroll', () => {
    const pos = chatMessagesDiv.scrollHeight - chatMessagesDiv.scrollTop - chatMessagesDiv.clientHeight;
    isAtBottom    = pos < 100;
    userScrolledUp = !isAtBottom;
    if (chatMessagesDiv.scrollTop === 0 && hasMoreMessages && !isLoadingMore) loadMoreMessages();
});

// ── Reply ─────────────────────────────────────────────────────────────────────
function startReply(id, uname, msg) {
    replyingTo = { id, username: uname, msg };
    replyUsername.textContent = uname;
    replyText.textContent = stripHtml(msg).substring(0, 120);
    replyPreview.style.display = 'flex';
    messageInput.focus();
}

function cancelReply() {
    replyingTo = null;
    if (replyPreview) replyPreview.style.display = 'none';
}
if (cancelReplyBtn) cancelReplyBtn.addEventListener('click', cancelReply);

// ── Send message ──────────────────────────────────────────────────────────────
function doSend() {
    const text = messageInput.value.trim();
    if (!text || !currentRoom) {
        if (!currentRoom) showOverlay('Select a chat first.');
        return;
    }
    if (text.length > MAX_MESSAGE_LENGTH) {
        showOverlay(`Message too long (max ${MAX_MESSAGE_LENGTH} chars).`);
        return;
    }
    const payload = { room: currentRoom, msg: text };
    if (replyingTo) payload.reply_to = replyingTo;
    socket.emit('send_message', payload);
    messageInput.value = '';
    charCounter.classList.remove('visible', 'warning', 'error');
    charCounter.textContent = `0 / ${MAX_MESSAGE_LENGTH}`;
    cancelReply();
    socket.emit('typing_stop', { room: currentRoom });
    messageInput.focus();
}

sendButton.addEventListener('click', doSend);
messageInput.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); doSend(); } });

// ── Build a message DOM element ───────────────────────────────────────────────
function buildMessageEl(msg) {
    const isSelf    = msg.username === username;
    const isDeleted = (msg.msg || '').includes('<em>deleted message</em>');

    const div = document.createElement('div');
    div.className = `message ${isSelf ? 'sent' : 'received'}`;
    div.dataset.messageId = msg.id;

    // Avatar
    const av = document.createElement('div');
    av.className = 'message-avatar';
    const prof = userProfiles[msg.username];
    if (prof && prof.profile_picture) {
        const img = document.createElement('img');
        img.src = prof.profile_picture;
        img.style.cssText = 'width:100%;height:100%;border-radius:50%;object-fit:cover;';
        av.appendChild(img);
    } else {
        av.textContent = (msg.username || '?')[0].toUpperCase();
    }

    // Content bubble
    const content = document.createElement('div');
    content.className = 'message-content';

    if (currentRoomType === 'group' || !isSelf) {
        const sender = document.createElement('div');
        sender.className = 'message-sender';
        sender.textContent = msg.username;
        content.appendChild(sender);
    }

    // Reply context
    if (msg.reply_to) {
        const ctx = document.createElement('div');
        ctx.className = 'message-reply-context';
        ctx.onclick = () => scrollToMessage(msg.reply_to.id);
        ctx.innerHTML = `<div class="message-reply-username">${msg.reply_to.username}</div>
                         <div class="message-reply-text">${stripHtml(msg.reply_to.msg).substring(0, 100)}</div>`;
        content.appendChild(ctx);
    }

    const textSpan = document.createElement('span');
    textSpan.innerHTML = msg.msg;
    content.appendChild(textSpan);

    const timeDiv = document.createElement('div');
    timeDiv.className = 'message-time';
    timeDiv.textContent = msg.time;
    content.appendChild(timeDiv);

    div.appendChild(av);
    div.appendChild(content);

    // Actions
    if (!isDeleted) {
        const actions = document.createElement('div');
        actions.className = 'message-actions';

        const replyBtn = document.createElement('button');
        replyBtn.className = 'reply-btn';
        replyBtn.title = 'Reply';
        replyBtn.innerHTML = '<i class="fas fa-reply"></i>';
        replyBtn.onclick = () => startReply(msg.id, msg.username, msg.msg);
        actions.appendChild(replyBtn);

        if (isSelf) {
            const editBtn = document.createElement('button');
            editBtn.title = 'Edit';
            editBtn.innerHTML = '<i class="fas fa-edit"></i>';
            editBtn.onclick = () => startEdit(msg.id, msg.msg);
            actions.appendChild(editBtn);

            const delBtn = document.createElement('button');
            delBtn.title = 'Delete';
            delBtn.innerHTML = '<i class="fas fa-trash"></i>';
            delBtn.onclick = () => doDelete(msg.id);
            actions.appendChild(delBtn);
        }

        div.appendChild(actions);
    }

    return div;
}

function addMessage(msg, prepend = false) {
    if (chatMessagesDiv.querySelector(`[data-message-id="${msg.id}"]`)) return;
    const el = buildMessageEl(msg);
    if (prepend) {
        const first = chatMessagesDiv.querySelector('.message');
        chatMessagesDiv.insertBefore(el, first || chatMessagesDiv.firstChild);
    } else {
        chatMessagesDiv.appendChild(el);
    }
}

function updateMessage(id, newText) {
    const el = chatMessagesDiv.querySelector(`[data-message-id="${id}"]`);
    if (!el) return;
    const span = el.querySelector('.message-content > span');
    if (span) span.innerHTML = newText;
    const actions = el.querySelector('.message-actions');
    if (actions && newText.includes('<em>deleted message</em>')) actions.remove();
}

// ── Edit message ──────────────────────────────────────────────────────────────
function startEdit(id, currentText) {
    const el = chatMessagesDiv.querySelector(`[data-message-id="${id}"]`);
    if (!el) return;
    const span = el.querySelector('.message-content > span');
    if (!span) return;
    if (el.querySelector('.message-edit-input')) return; // already editing

    const clean = currentText.replace(/<em>\(edited\)<\/em>/, '').replace(/<em>deleted message<\/em>/, '').trim();
    const input = document.createElement('input');
    input.type = 'text';
    input.value = clean;
    input.defaultValue = clean;
    input.maxLength = MAX_MESSAGE_LENGTH;
    input.className = 'message-edit-input';

    const actions = el.querySelector('.message-actions');
    if (actions) actions.style.visibility = 'hidden';

    let committed = false;
    function commit() {
        if (committed) return; committed = true;
        const newText = input.value.trim();
        if (!newText || newText === clean) {
            input.replaceWith(span);
            if (actions) actions.style.visibility = '';
            return;
        }
        socket.emit('edit_message', { message_id: id, new_text: newText, room: currentRoom });
        span.innerHTML = newText + ' <em>(edited)</em>';
        input.replaceWith(span);
        if (actions) actions.style.visibility = '';
    }

    input.addEventListener('keydown', e => {
        if (e.key === 'Enter')  { e.preventDefault(); commit(); }
        if (e.key === 'Escape') { committed = true; input.replaceWith(span); if (actions) actions.style.visibility = ''; }
    });
    input.addEventListener('blur', commit);

    span.replaceWith(input);
    input.focus(); input.select();
}

function doDelete(id) {
    if (!confirm('Delete this message?')) return;
    socket.emit('delete_message', { message_id: id, room: currentRoom });
}

// ── Chat history ──────────────────────────────────────────────────────────────
async function loadChatHistory(roomName) {
    if (isLoadingHistory) return;
    isLoadingHistory = true;
    chatMessagesDiv.innerHTML = '<div class="loading-messages">Loading messages…</div>';
    messageOffset = 0; hasMoreMessages = true;

    try {
        const resp = await fetch(`/history/${encodeURIComponent(roomName)}?offset=0&limit=50`);
        const data = await resp.json();

        // Guard: room changed while we were fetching
        if (currentRoom !== roomName) { isLoadingHistory = false; return; }

        chatMessagesDiv.innerHTML = '';

        if (data.error) {
            currentChatHeader.textContent = 'Error loading chat';
            setCallVisibility(null);
            isLoadingHistory = false;
            return;
        }

        const users = [...new Set(data.messages.map(m => m.username))];
        await loadUserProfiles(users);

        data.messages.forEach(m => addMessage(m));
        messageOffset   = data.messages.length;
        hasMoreMessages = data.has_more;

        userScrolledUp = false;
        scrollToBottom(true);
    } catch (err) {
        console.error('loadChatHistory:', err);
        chatMessagesDiv.innerHTML = '';
    } finally {
        isLoadingHistory = false;
    }
}

async function loadMoreMessages() {
    if (!currentRoom || isLoadingMore || !hasMoreMessages) return;
    isLoadingMore = true;

    const loader = document.createElement('div');
    loader.className = 'loading-messages';
    loader.textContent = 'Loading more…';
    chatMessagesDiv.prepend(loader);

    const prevHeight = chatMessagesDiv.scrollHeight;

    try {
        const resp = await fetch(`/history/${encodeURIComponent(currentRoom)}?offset=${messageOffset}&limit=50`);
        const data = await resp.json();
        loader.remove();

        if (data.messages && data.messages.length > 0) {
            const users = [...new Set(data.messages.map(m => m.username))];
            await loadUserProfiles(users);
            data.messages.forEach(m => addMessage(m, true));
            messageOffset += data.messages.length;
            hasMoreMessages = data.has_more;
            chatMessagesDiv.scrollTop = chatMessagesDiv.scrollHeight - prevHeight;
        } else {
            hasMoreMessages = false;
        }
    } catch (err) {
        loader.remove();
    } finally {
        isLoadingMore = false;
    }
}

// ── User profiles ─────────────────────────────────────────────────────────────
async function loadUserProfiles(usernames) {
    const needed = usernames.filter(u => !userProfiles[u]);
    if (!needed.length) return;
    try {
        const r = await fetch('/get_user_profiles', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usernames: needed }),
        });
        const profiles = await r.json();
        Object.assign(userProfiles, profiles);

        needed.forEach(u => {
            const av = document.getElementById(`avatar-${u}`);
            if (av && profiles[u]?.profile_picture) {
                av.innerHTML = `<img src="${profiles[u].profile_picture}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">`;
            }
        });
    } catch (_) {}
}

// ── Contact order + last-message preview ──────────────────────────────────────
async function loadContactsWithTimestamps() {
    try {
        const r = await fetch('/get_contacts_order');
        const data = await r.json();
        if (!data.contacts) return;

        const map = {};
        data.contacts.forEach(c => { map[c.id] = c; });

        const items = Array.from(friendListUl.querySelectorAll('li[data-friend-username], li[data-room-id]'));
        items.sort((a, b) => {
            const aId = a.dataset.roomId || a.dataset.friendUsername;
            const bId = b.dataset.roomId || b.dataset.friendUsername;
            return (map[bId]?.last_message_timestamp || 0) - (map[aId]?.last_message_timestamp || 0);
        });

        // Clear unread badges before re-appending
        items.forEach(item => {
            const id = item.dataset.roomId || item.dataset.friendUsername;
            const badge = item.querySelector('.unread-indicator');
            if (badge) badge.remove();

            const stored = JSON.parse(localStorage.getItem('unreadCounts') || '{}');
            const count = stored[id] || 0;
            if (count > 0) {
                const b = document.createElement('span');
                b.className = 'unread-indicator';
                b.textContent = count;
                const ns = item.querySelector('.contact-name span') || item.querySelector('span');
                if (ns) ns.appendChild(b);
            }

            const preview = item.querySelector('.last-message-preview');
            if (preview && map[id]) {
                const raw = stripHtml(map[id].last_message_text || '');
                preview.textContent = raw.length > 42 ? raw.substring(0, 42) + '…' : raw;
            }

            friendListUl.appendChild(item);
        });
    } catch (_) {}
}

// ── Room / friend selection ───────────────────────────────────────────────────
function setCallVisibility(roomType) {
    if (callIcons)      callIcons.style.display      = roomType === 'direct' ? 'flex' : 'none';
    if (groupCallIcons) groupCallIcons.style.display = roomType === 'group'  ? 'flex' : 'none';
    if (editGroupBtn)   editGroupBtn.style.display   = roomType === 'group'  ? 'inline' : 'none';
}

function selectRoom(roomId, roomType, roomName, targetLi = null) {
    // Clear unread badge
    if (targetLi) {
        targetLi.querySelector('.unread-indicator')?.remove();
        const stored = JSON.parse(localStorage.getItem('unreadCounts') || '{}');
        delete stored[roomId];
        localStorage.setItem('unreadCounts', JSON.stringify(stored));
    }

    if (currentRoom) socket.emit('leave', { room: currentRoom });

    currentRoom     = roomId;
    currentRoomType = roomType;
    window.currentRoom      = roomId;
    window.currentGroupRoom = roomType === 'group' ? roomId : null;

    messageOffset = 0; hasMoreMessages = true; userScrolledUp = false; isAtBottom = true;

    socket.emit('join', { room: roomId });

    friendListUl.querySelectorAll('li').forEach(li => li.classList.remove('active'));
    if (targetLi) targetLi.classList.add('active');

    if (selectChatPrompt) selectChatPrompt.style.display = 'none';
    setCallVisibility(roomType);
    cancelReply();

    const displayName = roomType === 'group' ? roomName : roomId.replace(username + '-', '').replace('-' + username, '');
    currentChatHeader.textContent = displayName;
    if (mobileChatTitle) mobileChatTitle.textContent = displayName;

    loadChatHistory(roomId);
}

function selectFriend(friendUsername, targetLi = null) {
    const roomId = [username, friendUsername].sort().join('-');
    if (targetLi) {
        targetLi.querySelector('.unread-indicator')?.remove();
        const stored = JSON.parse(localStorage.getItem('unreadCounts') || '{}');
        delete stored[friendUsername];
        localStorage.setItem('unreadCounts', JSON.stringify(stored));
    }
    selectRoom(roomId, 'direct', friendUsername,
        targetLi || friendListUl.querySelector(`li[data-friend-username="${friendUsername}"]`));
}

// Sidebar click delegation
friendListUl.addEventListener('click', e => {
    const li = e.target.closest('li[data-friend-username], li[data-room-id]');
    if (!li) return;
    if (window.innerWidth < 768) sidebar.classList.remove('active');

    if (li.dataset.roomType === 'group') {
        localStorage.setItem('activeRoom', li.dataset.roomId);
        localStorage.setItem('activeRoomType', 'group');
        selectRoom(li.dataset.roomId, 'group', li.dataset.roomName, li);
    } else {
        const fn = li.dataset.friendUsername;
        localStorage.setItem('activeFriend', fn);
        localStorage.setItem('activeRoomType', 'direct');
        selectFriend(fn, li);
    }
});

// ── Socket: incoming messages ─────────────────────────────────────────────────
socket.on('message', data => {
    if (!userProfiles[data.username]) loadUserProfiles([data.username]);

    if (data.room === currentRoom) {
        addMessage(data);
        if (isAtBottom) scrollToBottom();
        if (data.username !== username) notify(`${data.username}`, stripHtml(data.msg).substring(0, 80), data.room);
    } else if (data.username !== username) {
        // Background chat — update badge + preview
        let li = data.room.startsWith('group_')
            ? friendListUl.querySelector(`li[data-room-id="${data.room}"]`)
            : friendListUl.querySelector(`li[data-friend-username="${data.room.replace(username + '-', '').replace('-' + username, '')}"]`);

        const badgeKey = data.room.startsWith('group_')
            ? data.room
            : data.room.replace(username + '-', '').replace('-' + username, '');

        if (li) {
            li.parentNode.prepend(li);
            const stored = JSON.parse(localStorage.getItem('unreadCounts') || '{}');
            stored[badgeKey] = (stored[badgeKey] || 0) + 1;
            localStorage.setItem('unreadCounts', JSON.stringify(stored));

            let badge = li.querySelector('.unread-indicator');
            if (!badge) {
                badge = document.createElement('span');
                badge.className = 'unread-indicator';
                const ns = li.querySelector('.contact-name span') || li.querySelector('span');
                if (ns) ns.appendChild(badge);
            }
            badge.textContent = stored[badgeKey];

            const preview = li.querySelector('.last-message-preview');
            if (preview) {
                const raw = stripHtml(data.msg);
                preview.textContent = raw.length > 42 ? raw.substring(0, 42) + '…' : raw;
            }

            const chatName = li.dataset.roomName || li.dataset.friendUsername || data.room;
            notify(`${data.username} · ${chatName}`, stripHtml(data.msg).substring(0, 80), data.room);
        }
    }
});

// ── Socket: message edits / deletes ──────────────────────────────────────────
socket.on('message_updated', data => {
    if (data.room !== currentRoom) return;
    let text = data.new_text;
    // Don't double-append "(edited)"
    if (!text.includes('<em>deleted message</em>') && !text.includes('<em>(edited)</em>')) {
        text += ' <em>(edited)</em>';
    }
    updateMessage(data.id, text);
});

// ── Socket: typing indicator ──────────────────────────────────────────────────
socket.on('user_typing', data => {
    const existing = document.getElementById('typing-indicator');
    if (data.is_typing) {
        if (!existing) {
            const ind = document.createElement('div');
            ind.id = 'typing-indicator';
            ind.className = 'typing-indicator';
            ind.innerHTML = `<span>${data.username} is typing…</span>`;
            chatMessagesDiv.appendChild(ind);
            if (isAtBottom) scrollToBottom();
        }
    } else {
        existing?.remove();
    }
});

// ── Socket: online/offline status ────────────────────────────────────────────
socket.on('user_status_update', data => {
    const dot = document.querySelector(`.status-indicator[data-username="${data.username}"]`);
    if (dot) { dot.className = 'status-indicator ' + (data.status || 'offline'); }
});

socket.on('all_statuses', data => {
    Object.entries(data).forEach(([u, info]) => {
        const dot = document.querySelector(`.status-indicator[data-username="${u}"]`);
        if (dot) dot.className = 'status-indicator ' + (info.status || 'offline');
    });
});

// ── Socket: error handling ────────────────────────────────────────────────────
socket.on('error', data => {
    const msg = data.message || '';
    if (msg.includes('not friends') || msg.includes('blocked') || msg.includes('not a member')) {
        currentRoom = null; window.currentRoom = null;
        chatMessagesDiv.innerHTML = '';
        currentChatHeader.textContent = '';
        setCallVisibility(null);
        if (selectChatPrompt) selectChatPrompt.style.display = 'block';
    } else {
        // Non-fatal — show briefly then auto-hide after 4 s
        showOverlay(msg);
        setTimeout(hideOverlay, 4000);
    }
});

// ── Group management ──────────────────────────────────────────────────────────
createGroupBtn?.addEventListener('click', () => {
    if (groupModalTitle) groupModalTitle.innerHTML = '<i class="fas fa-users"></i> Create New Group';
    if (createGroupForm) createGroupForm.style.display = 'flex';
    if (editGroupForm)   editGroupForm.style.display   = 'none';
    if (groupModal)      groupModal.classList.add('active');
    if (groupNameInput)  groupNameInput.value = '';
    document.querySelectorAll('#member-selection input[type="checkbox"]').forEach(cb => { cb.checked = false; });
});

cancelGroupBtn?.addEventListener('click',     () => groupModal?.classList.remove('active'));
cancelEditGroupBtn?.addEventListener('click', () => {
    groupModal?.classList.remove('active');
    if (addMembersSection) addMembersSection.style.display = 'none';
});

createGroupSubmit?.addEventListener('click', async () => {
    const name    = groupNameInput?.value.trim();
    const members = Array.from(document.querySelectorAll('#member-selection input:checked')).map(c => c.value);
    if (!name)             { showOverlay('Enter a group name.'); return; }
    if (!members.length)   { showOverlay('Select at least 1 member.'); return; }

    const r = await fetch('/create_group', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, members }),
    });
    const d = await r.json();
    if (d.error) { showOverlay(d.error); return; }

    groupModal?.classList.remove('active');
    addGroupToSidebar(d.group_id, d.group_name);
    showOverlay('Group created!');
    setTimeout(hideOverlay, 2500);
});

// Edit group
editGroupBtn?.addEventListener('click', async () => {
    if (!currentRoom?.startsWith('group_')) return;
    const r = await fetch(`/get_group_info/${currentRoom}`);
    const data = await r.json();
    if (data.error) { showOverlay(data.error); return; }

    window._currentGroupInfo = data;
    if (groupModalTitle) groupModalTitle.innerHTML = '<i class="fas fa-edit"></i> Edit Group';
    if (createGroupForm) createGroupForm.style.display = 'none';
    if (editGroupForm)   editGroupForm.style.display   = 'flex';
    if (editGroupNameInput) editGroupNameInput.value   = data.name;

    if (groupMembersList) {
        groupMembersList.innerHTML = '';
        data.members.forEach(m => {
            const item = document.createElement('div');
            item.className = 'group-member-item';
            item.innerHTML = `
                <div class="member-info">
                    <div class="member-avatar">${m.username[0].toUpperCase()}</div>
                    <span>${m.username}${m.username === data.creator ? ' <span class="creator-badge">Creator</span>' : ''}</span>
                </div>
                ${data.is_creator && m.username !== data.creator
                    ? `<button class="kick-btn" data-u="${m.username}"><i class="fas fa-times"></i> Kick</button>` : ''}`;
            groupMembersList.appendChild(item);
        });
        groupMembersList.querySelectorAll('.kick-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                if (!confirm(`Kick ${btn.dataset.u}?`)) return;
                const kr = await fetch(`/update_group/${currentRoom}`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'kick', member: btn.dataset.u }),
                });
                const kd = await kr.json();
                if (kd.error) showOverlay(kd.error); else editGroupBtn.click();
            });
        });
    }

    if (showAddMembersBtn) showAddMembersBtn.style.display = data.is_creator ? 'inline-flex' : 'none';
    if (leaveGroupBtn)     leaveGroupBtn.style.display     = data.is_creator ? 'none' : 'inline-flex';
    groupModal?.classList.add('active');
});

saveGroupBtn?.addEventListener('click', async () => {
    const name = editGroupNameInput?.value.trim();
    if (!name) { showOverlay('Group name cannot be empty.'); return; }
    const r = await fetch(`/update_group/${currentRoom}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'rename', name }),
    });
    const d = await r.json();
    if (d.error) { showOverlay(d.error); return; }
    currentChatHeader.textContent = name;
    const li = friendListUl.querySelector(`li[data-room-id="${currentRoom}"]`);
    if (li) {
        li.dataset.roomName = name;
        const sp = li.querySelector('.contact-name span');
        if (sp) sp.innerHTML = `${name} <span class="group-indicator">GROUP</span>`;
    }
    groupModal?.classList.remove('active');
});

showAddMembersBtn?.addEventListener('click', () => {
    if (!addMemberSelection || !window._currentGroupInfo) return;
    addMemberSelection.innerHTML = '';
    const current = window._currentGroupInfo.members.map(m => m.username);
    friendListUl.querySelectorAll('li[data-friend-username]').forEach(li => {
        const fn = li.dataset.friendUsername;
        if (!current.includes(fn)) {
            addMemberSelection.innerHTML += `
                <div class="member-checkbox">
                    <input type="checkbox" id="add-${fn}" value="${fn}">
                    <label for="add-${fn}">${fn}</label>
                </div>`;
        }
    });
    if (addMembersSection) addMembersSection.style.display = 'block';
});

confirmAddMembers?.addEventListener('click', async () => {
    const sel = Array.from(addMemberSelection?.querySelectorAll('input:checked') || []).map(c => c.value);
    if (!sel.length) { showOverlay('Select at least one member.'); return; }
    const r = await fetch(`/update_group/${currentRoom}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'add_members', members: sel }),
    });
    const d = await r.json();
    if (d.error) { showOverlay(d.error); return; }
    if (addMembersSection) addMembersSection.style.display = 'none';
    groupModal?.classList.remove('active');
    showOverlay(`Added: ${sel.join(', ')}`);
    setTimeout(hideOverlay, 2500);
});

leaveGroupBtn?.addEventListener('click', async () => {
    if (!confirm('Leave this group?')) return;
    const r = await fetch(`/update_group/${currentRoom}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'leave' }),
    });
    const d = await r.json();
    if (d.error) { showOverlay(d.error); return; }
    friendListUl.querySelector(`li[data-room-id="${currentRoom}"]`)?.remove();
    currentRoom = null; window.currentRoom = null;
    chatMessagesDiv.innerHTML = '';
    currentChatHeader.textContent = '';
    setCallVisibility(null);
    if (selectChatPrompt) selectChatPrompt.style.display = 'block';
    groupModal?.classList.remove('active');
});

// ── Media / file handling ─────────────────────────────────────────────────────
function showMediaPreview(file) {
    if (!currentRoom) { showOverlay('Select a chat first.'); return; }
    pendingMediaFile = file;
    mediaPreviewContainer.innerHTML = '';
    const url = URL.createObjectURL(file);
    const el = file.type.startsWith('video/')
        ? Object.assign(document.createElement('video'), { controls: true, src: url })
        : Object.assign(document.createElement('img'), { src: url });
    mediaPreviewContainer.appendChild(el);
    mediaPreviewModal?.classList.add('active');
}

fileInput?.addEventListener('change', e => {
    const f = e.target.files[0];
    if (f) showMediaPreview(f);
    fileInput.value = '';
});

messageInput?.addEventListener('paste', e => {
    for (const item of e.clipboardData.items) {
        if (item.type.startsWith('image/') || item.type.startsWith('video/')) {
            e.preventDefault();
            showMediaPreview(item.getAsFile());
            break;
        }
    }
});

sendMediaBtn?.addEventListener('click', async () => {
    if (!pendingMediaFile) return;
    mediaPreviewModal?.classList.remove('active');

    const fd = new FormData();
    fd.append('file', pendingMediaFile);
    try {
        const r = await fetch('/upload_file', { method: 'POST', body: fd });
        const d = await r.json();
        if (d.error) { showOverlay('Upload failed: ' + d.error); return; }
        if (d.url) {
            const ext  = (pendingMediaFile.name || '').split('.').pop().toLowerCase();
            const isImg = pendingMediaFile.type.startsWith('image/') || ['png','jpg','jpeg','gif','webp'].includes(ext);
            const isVid = pendingMediaFile.type.startsWith('video/') || ['mp4','webm','ogg','mov'].includes(ext);
            const msg = isImg ? `<a href="${d.url}" target="_blank"><img src="${d.url}" class="message-file image" alt="image"></a>`
                      : isVid ? `<video controls src="${d.url}" class="message-file video"></video>`
                      : `<a href="${d.url}" target="_blank">${pendingMediaFile.name || 'file'}</a>`;
            const payload = { room: currentRoom, msg };
            if (replyingTo) payload.reply_to = replyingTo;
            socket.emit('send_message', payload);
            cancelReply();
        }
    } catch (err) {
        showOverlay('Upload error.');
    } finally {
        pendingMediaFile = null;
    }
});

cancelMediaBtn?.addEventListener('click', () => {
    mediaPreviewModal?.classList.remove('active');
    mediaPreviewContainer.innerHTML = '';
    pendingMediaFile = null;
});

// ── Mobile keyboard ───────────────────────────────────────────────────────────
const chatArea = document.querySelector('.chat-area');
let aboutToSend = false;
sendButton?.addEventListener('mousedown',  () => { aboutToSend = true; });
sendButton?.addEventListener('touchstart', () => { aboutToSend = true; });
messageInput?.addEventListener('focus', () => {
    if (window.innerWidth > 768) return;
    if (chatArea) chatArea.style.paddingBottom = '20vh';
    setTimeout(() => messageInput.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 150);
});
messageInput?.addEventListener('blur', () => {
    if (window.innerWidth <= 768) {
        setTimeout(() => { if (!aboutToSend && chatArea) chatArea.style.paddingBottom = '0'; aboutToSend = false; }, 300);
    }
});

// ── Bootstrap: poll friend requests + initial load ────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    pollFriendRequests();
    setInterval(pollFriendRequests, 30_000);
    loadContactsWithTimestamps();
});