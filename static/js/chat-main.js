// Initialize Socket.IO and variables
const socket = io();
const username = document.querySelector('.username').textContent;
const MAX_MESSAGE_LENGTH = parseInt(document.getElementById('message-input').maxLength);

// Chat state variables
let currentRoom = null;
let currentRoomType = 'direct';
let isLoadingHistory = false;
let userStatus = 'offline';
let typingTimeout = null;
let connectedUsers = {};
let replyingTo = null;
let messageOffset = 0;
let hasMoreMessages = true;
let isLoadingMore = false;
let pendingMediaFile = null;
let userProfiles = {};
let currentGroupInfo = null;
let userScrolledUp = false;
let isAtBottom = true;
let isConnected = socket.connected;
let reconnectInterval = null;

// Page visibility tracking
let isPageVisible = true;
let isPageFocused = true;

// DOM Elements
const sidebar = document.getElementById('sidebar');
const menuToggle = document.getElementById('menu-toggle');
const closeSidebarButton = document.getElementById('close-sidebar-button');
const chatMessagesDiv = document.getElementById('chat-messages');
const messageInput = document.getElementById('message-input');
const sendButton = document.getElementById('send-button');
const currentChatHeader = document.getElementById('current-chat-header');
const friendListUl = document.getElementById('friend-list-ul');
const fileInput = document.getElementById('file-input');
const statusOverlay = document.getElementById('status-overlay');
const overlayMessage = document.getElementById('overlay-message');
const selectChatPrompt = document.getElementById('select-chat-prompt');
const contactSearch = document.getElementById('contact-search');
const charCounter = document.getElementById('char-counter');
const notificationSound = document.getElementById('notification-sound');

// Group modal elements
const createGroupBtn = document.getElementById('create-group-btn');
const groupModal = document.getElementById('group-modal');
const groupModalTitle = document.getElementById('group-modal-title');
const createGroupForm = document.getElementById('create-group-form');
const editGroupForm = document.getElementById('edit-group-form');
const cancelGroupBtn = document.getElementById('cancel-group-btn');
const cancelEditGroupBtn = document.getElementById('cancel-edit-group-btn');
const createGroupSubmit = document.getElementById('create-group-submit');
const groupNameInput = document.getElementById('group-name-input');
const editGroupNameInput = document.getElementById('edit-group-name-input');
const saveGroupBtn = document.getElementById('save-group-btn');
const leaveGroupBtn = document.getElementById('leave-group-btn');
const groupMembersList = document.getElementById('group-members-list');
const editGroupBtn = document.getElementById('edit-group-btn');
const showAddMembersBtn = document.getElementById('show-add-members-btn');
const addMembersSection = document.getElementById('add-members-section');
const addMemberSelection = document.getElementById('add-member-selection');
const confirmAddMembers = document.getElementById('confirm-add-members');

// Reply elements
const replyPreview = document.getElementById('reply-preview');
const replyUsername = document.getElementById('reply-username');
const replyText = document.getElementById('reply-text');
const cancelReplyBtn = document.getElementById('cancel-reply');

// Media preview elements
const mediaPreviewModal = document.getElementById('media-preview-modal');
const mediaPreviewContainer = document.getElementById('media-preview-container');
const sendMediaBtn = document.getElementById('send-media-btn');
const cancelMediaBtn = document.getElementById('cancel-media-btn');

// Call icon elements
const callIcons = document.getElementById('call-icons');

// ============================================
// SOCKET CONNECTION MANAGEMENT
// ============================================

socket.on('connect', () => {
    isConnected = true;
    if (reconnectInterval) {
        clearInterval(reconnectInterval);
        reconnectInterval = null;
    }
    console.log('Connected to Socket.IO');
    socket.emit('user_connected');
    userStatus = 'online';
    socket.emit('request_statuses');
    
    const friendUsernames = Array.from(friendListUl.querySelectorAll('li[data-friend-username]'))
        .map(li => li.dataset.friendUsername);
    if (friendUsernames.length > 0) {
        loadUserProfiles(friendUsernames);
        loadContactsWithTimestamps();
    }
    
    const storedRoomType = localStorage.getItem('activeRoomType');
    if (storedRoomType === 'group') {
        const storedRoom = localStorage.getItem('activeRoom');
        if (storedRoom) {
            const groupLi = friendListUl.querySelector(`li[data-room-id="${storedRoom}"]`);
            if (groupLi) {
                selectRoom(storedRoom, 'group', groupLi.dataset.roomName, groupLi);
            }
        }
    } else {
        const storedFriend = localStorage.getItem('activeFriend');
        if (storedFriend) {
            selectFriend(storedFriend);
        }
    }
});

socket.on('disconnect', () => {
    isConnected = false;
    console.log('Disconnected from Socket.IO');
    showOverlay("Disconnected from chat server. Attempting to reconnect...");
    
    if (!reconnectInterval) {
        reconnectInterval = setInterval(() => {
            if (!socket.connected) {
                console.log('Attempting manual reconnection...');
                socket.connect();
            } else {
                clearInterval(reconnectInterval);
                reconnectInterval = null;
            }
        }, 3000);
    }
});

socket.on('reconnect', (attemptNumber) => {
    console.log('Reconnected to Socket.IO');
    hideOverlay();
    if (currentRoom) {
        socket.emit('join', { room: currentRoom });
    }
    socket.emit('user_connected');
    userStatus = 'online';
    socket.emit('request_statuses');
    loadContactsWithTimestamps();
});

// ============================================
// UTILITY FUNCTIONS
// ============================================

function showOverlay(message) {
    overlayMessage.textContent = message;
    statusOverlay.classList.add('active');
}

function hideOverlay() {
    statusOverlay.classList.remove('active');
}

function scrollToBottom() {
    if (!userScrolledUp) {
        setTimeout(() => {
            chatMessagesDiv.scrollTop = chatMessagesDiv.scrollHeight;
        }, 100);
    }
}

function stripHtmlForPreview(html) {
    const div = document.createElement('div');
    div.innerHTML = html;
    return div.textContent || div.innerText || '';
}

function scrollToMessage(messageId) {
    const messageElement = chatMessagesDiv.querySelector(`[data-message-id="${messageId}"]`);
    if (messageElement) {
        messageElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
        messageElement.classList.add('highlighted');
        setTimeout(() => {
            messageElement.classList.remove('highlighted');
        }, 1000);
    }
}

// ============================================
// NOTIFICATION FUNCTIONS
// ============================================

document.addEventListener('visibilitychange', () => {
    isPageVisible = !document.hidden;
    if (isPageVisible) {
        document.title = document.title.replace(/^\(New message\) /, '').replace(/^\(\d+\) /, '');
    }
});

window.addEventListener('focus', () => {
    isPageFocused = true;
    document.title = document.title.replace(/^\(New message\) /, '').replace(/^\(\d+\) /, '');
});

window.addEventListener('blur', () => {
    isPageFocused = false;
});

function showNotificationAndPlaySound(title, body, dataRoom) {
    const shouldNotify = !isPageFocused || !isPageVisible;
    
    if (shouldNotify) {
        if (Notification.permission === 'granted') {
            const notification = new Notification(title, { 
                body: body, 
                tag: dataRoom,
                icon: '/static/favicon.ico',
                requireInteraction: false
            });
            
            notification.onclick = () => {
                window.focus();
                notification.close();
            };
        }
        
        if (notificationSound) {
            notificationSound.currentTime = 0;
            notificationSound.play().catch(e => console.log("Audio play failed:", e));
        }
        
        const currentTitle = document.title;
        if (!currentTitle.includes('New message')) {
            document.title = `(New message) ${currentTitle.replace(/^\(\d+\) /, '')}`;
        }
    }
}

// Request notification permission
if (Notification.permission !== 'granted' && Notification.permission !== 'denied') {
    Notification.requestPermission();
}

// ============================================
// UI EVENT LISTENERS
// ============================================

menuToggle.addEventListener('click', () => {
    sidebar.classList.add('active');
});

closeSidebarButton.addEventListener('click', () => {
    sidebar.classList.remove('active');
});

messageInput.addEventListener('input', () => {
    const length = messageInput.value.length;
    charCounter.textContent = `${length} / ${MAX_MESSAGE_LENGTH}`;
    
    if (length > 0) {
        charCounter.classList.add('visible');
    } else {
        charCounter.classList.remove('visible');
    }
    
    if (length > MAX_MESSAGE_LENGTH * 0.9) {
        charCounter.classList.add('warning');
    } else {
        charCounter.classList.remove('warning');
    }
    
    if (length >= MAX_MESSAGE_LENGTH) {
        charCounter.classList.add('error');
    } else {
        charCounter.classList.remove('error');
    }
    
    if (currentRoom) {
        socket.emit('typing_start', { room: currentRoom });
        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(() => {
            socket.emit('typing_stop', { room: currentRoom });
        }, 1000);
    }
});

chatMessagesDiv.addEventListener('scroll', () => {
    const threshold = 100;
    const position = chatMessagesDiv.scrollHeight - chatMessagesDiv.scrollTop - chatMessagesDiv.clientHeight;
    isAtBottom = position < threshold;
    userScrolledUp = !isAtBottom;
    
    if (chatMessagesDiv.scrollTop === 0 && hasMoreMessages && !isLoadingMore) {
        loadMoreMessages();
    }
});

contactSearch.addEventListener('input', (e) => {
    const searchTerm = e.target.value.toLowerCase();
    const allContacts = friendListUl.querySelectorAll('li[data-friend-username], li[data-room-id]');
    
    allContacts.forEach(contact => {
        const name = contact.querySelector('span').textContent.toLowerCase();
        if (name.includes(searchTerm)) {
            contact.style.display = 'flex';
        } else {
            contact.style.display = 'none';
        }
    });
});

// ============================================
// MESSAGE FUNCTIONS
// ============================================

function addMessage(msg, prepend = false) {
    const messageDiv = document.createElement('div');
    messageDiv.classList.add('message');
    messageDiv.setAttribute('data-message-id', msg.id);
    
    if (msg.username === username) {
        messageDiv.classList.add('sent');
    } else {
        messageDiv.classList.add('received');
    }
    
    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    
    if (userProfiles[msg.username] && userProfiles[msg.username].profile_picture) {
        const img = document.createElement('img');
        img.src = userProfiles[msg.username].profile_picture;
        img.style.width = '100%';
        img.style.height = '100%';
        img.style.borderRadius = '50%';
        img.style.objectFit = 'cover';
        avatarDiv.appendChild(img);
    } else {
        avatarDiv.textContent = msg.username[0].toUpperCase();
    }
    
    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content');
    
    if (currentRoomType === 'group' || msg.username !== username) {
        const senderSpan = document.createElement('div');
        senderSpan.classList.add('message-sender');
        senderSpan.textContent = msg.username;
        contentDiv.appendChild(senderSpan);
    }
    
    if (msg.reply_to) {
        const replyContext = document.createElement('div');
        replyContext.classList.add('message-reply-context');
        replyContext.onclick = () => scrollToMessage(msg.reply_to.id);
        
        const replyUserDiv = document.createElement('div');
        replyUserDiv.classList.add('message-reply-username');
        replyUserDiv.textContent = msg.reply_to.username;
        
        const replyTextDiv = document.createElement('div');
        replyTextDiv.classList.add('message-reply-text');
        replyTextDiv.textContent = stripHtmlForPreview(msg.reply_to.msg);
        
        replyContext.appendChild(replyUserDiv);
        replyContext.appendChild(replyTextDiv);
        contentDiv.appendChild(replyContext);
    }
    
    const textSpan = document.createElement('span');
    textSpan.innerHTML = msg.msg;
    
    const timeSpan = document.createElement('div');
    timeSpan.classList.add('message-time');
    timeSpan.textContent = msg.time;
    
    contentDiv.appendChild(textSpan);
    contentDiv.appendChild(timeSpan);
    
    messageDiv.appendChild(avatarDiv);
    messageDiv.appendChild(contentDiv);
    
    if (msg.username === username && !msg.msg.includes("<em>deleted message</em>")) {
        const actionsDiv = document.createElement('div');
        actionsDiv.classList.add('message-actions');
        
        const replyButton = document.createElement('button');
        replyButton.innerHTML = '<i class="fas fa-reply"></i>';
        replyButton.classList.add('reply-btn');
        replyButton.title = 'Reply';
        replyButton.onclick = () => startReply(msg.id, msg.username, msg.msg);
        
        const editButton = document.createElement('button');
        editButton.innerHTML = '<i class="fas fa-edit"></i>';
        editButton.title = 'Edit';
        editButton.onclick = () => startEditMessage(msg.id, msg.msg);
        
        const deleteButton = document.createElement('button');
        deleteButton.innerHTML = '<i class="fas fa-trash"></i>';
        deleteButton.title = 'Delete';
        deleteButton.onclick = () => deleteMessage(msg.id);
        
        actionsDiv.appendChild(replyButton);
        actionsDiv.appendChild(editButton);
        actionsDiv.appendChild(deleteButton);
        messageDiv.appendChild(actionsDiv);
    } else if (msg.username !== username && !msg.msg.includes("<em>deleted message</em>")) {
        const actionsDiv = document.createElement('div');
        actionsDiv.classList.add('message-actions');
        
        const replyButton = document.createElement('button');
        replyButton.innerHTML = '<i class="fas fa-reply"></i>';
        replyButton.classList.add('reply-btn');
        replyButton.title = 'Reply';
        replyButton.onclick = () => startReply(msg.id, msg.username, msg.msg);
        
        actionsDiv.appendChild(replyButton);
        messageDiv.appendChild(actionsDiv);
    }
    
    if (prepend) {
        const firstMsg = chatMessagesDiv.querySelector('.message');
        if (firstMsg) {
            chatMessagesDiv.insertBefore(messageDiv, firstMsg);
        } else {
            chatMessagesDiv.appendChild(messageDiv);
        }
    } else {
        chatMessagesDiv.appendChild(messageDiv);
    }
}

function startReply(messageId, messageUsername, messageText) {
    replyingTo = {
        id: messageId,
        username: messageUsername,
        msg: messageText
    };
    replyUsername.textContent = messageUsername;
    replyText.textContent = stripHtmlForPreview(messageText);
    replyPreview.style.display = 'flex';
    messageInput.focus();
}

function cancelReply() {
    replyingTo = null;
    replyPreview.style.display = 'none';
}

cancelReplyBtn.addEventListener('click', cancelReply);

function updateMessage(messageId, newText) {
    const messageElement = chatMessagesDiv.querySelector(`[data-message-id="${messageId}"]`);
    if (messageElement) {
        const textSpan = messageElement.querySelector('.message-content span');
        if (textSpan) {
            textSpan.innerHTML = newText;
            const actionsDiv = messageElement.querySelector('.message-actions');
            if (actionsDiv) {
                if (newText.includes("<em>deleted message</em>")) {
                    actionsDiv.style.display = 'none';
                } else {
                    if (messageElement.classList.contains('sent')) {
                        actionsDiv.style.display = '';
                    }
                }
            }
        }
    }
}

function startEditMessage(messageId, currentMessageText) {
    const messageElement = chatMessagesDiv.querySelector(`[data-message-id="${messageId}"]`);
    if (!messageElement) return;
    
    const textSpan = messageElement.querySelector('.message-content span');
    if (!textSpan) return;
    
    const existingInput = messageElement.querySelector('.message-edit-input');
    if (existingInput) existingInput.remove();
    
    const cleanText = currentMessageText.replace(/<em>\(edited\)<\/em>/, '').trim();
    const input = document.createElement('input');
    input.type = 'text';
    input.value = cleanText;
    input.maxLength = MAX_MESSAGE_LENGTH;
    input.classList.add('message-edit-input');
    
    input.onkeypress = (e) => {
        if (e.key === 'Enter') {
            confirmEditMessage(messageId, input.value, input);
            e.preventDefault();
        }
    };
    
    input.onblur = () => {
        confirmEditMessage(messageId, input.value, input, true);
    };
    
    const actionsDiv = messageElement.querySelector('.message-actions');
    if (actionsDiv) actionsDiv.style.display = 'none';
    
    textSpan.replaceWith(input);
    input.focus();
    input.select();
}

function confirmEditMessage(messageId, newText, inputElement, onBlur = false) {
    const originalText = inputElement.defaultValue;
    const messageElement = chatMessagesDiv.querySelector(`[data-message-id="${messageId}"]`);
    const textSpan = document.createElement('span');
    
    if (newText.trim() === '' && !onBlur) {
        showOverlay("Message cannot be empty.");
        textSpan.innerHTML = originalText;
        inputElement.replaceWith(textSpan);
        const actionsDiv = messageElement.querySelector('.message-actions');
        if (actionsDiv) actionsDiv.style.display = '';
        return;
    } else if (newText.trim() === '' || newText === originalText) {
        textSpan.innerHTML = originalText;
        inputElement.replaceWith(textSpan);
        const actionsDiv = messageElement.querySelector('.message-actions');
        if (actionsDiv) actionsDiv.style.display = '';
        return;
    }
    
    if (newText.length > MAX_MESSAGE_LENGTH) {
        showOverlay(`Message too long. Maximum ${MAX_MESSAGE_LENGTH} characters allowed.`);
        textSpan.innerHTML = originalText;
        inputElement.replaceWith(textSpan);
        const actionsDiv = messageElement.querySelector('.message-actions');
        if (actionsDiv) actionsDiv.style.display = '';
        return;
    }
    
    socket.emit('edit_message', {
        message_id: messageId,
        new_text: newText,
        room: currentRoom
    });
    
    textSpan.innerHTML = newText + ' <em>(edited)</em>';
    inputElement.replaceWith(textSpan);
    const actionsDiv = messageElement.querySelector('.message-actions');
    if (actionsDiv) actionsDiv.style.display = '';
}

function deleteMessage(messageId) {
    if (confirm("Are you sure you want to delete this message?")) {
        socket.emit('delete_message', {
            message_id: messageId,
            room: currentRoom
        });
    }
}

sendButton.addEventListener('click', () => {
    if (!socket.connected) {
        showOverlay("You are disconnected. Please wait while we reconnect...");
        return;
    }
    
    const messageText = messageInput.value.trim();
    if (messageText && currentRoom) {
        if (messageText.length > MAX_MESSAGE_LENGTH) {
            showOverlay(`Message too long. Maximum ${MAX_MESSAGE_LENGTH} characters allowed.`);
            return;
        }
        
        const messageData = {
            username: username,
            room: currentRoom,
            msg: messageText
        };
        
        if (replyingTo) {
            messageData.reply_to = replyingTo;
        }
        
        socket.emit('send_message', messageData);
        messageInput.value = '';
        charCounter.classList.remove('visible', 'warning', 'error');
        charCounter.textContent = `0 / ${MAX_MESSAGE_LENGTH}`;
        messageInput.focus();
        cancelReply();
        socket.emit('typing_stop', { room: currentRoom });
        loadContactsWithTimestamps();
    } else if (!currentRoom) {
        showOverlay("Please select a friend or group to chat with first.");
    }
});

messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        sendButton.click();
    }
});

// ============================================
// CHAT HISTORY AND ROOM MANAGEMENT
// ============================================

async function loadChatHistory(roomName) {
    if (isLoadingHistory) return;
    
    const loadingRoomName = roomName;
    isLoadingHistory = true;
    chatMessagesDiv.innerHTML = '<div class="loading-messages">Loading messages...</div>';
    messageOffset = 0;
    hasMoreMessages = true;
    
    if (roomName.startsWith('group_')) {
        const groupLi = friendListUl.querySelector(`li[data-room-id="${roomName}"]`);
        if (groupLi) {
            currentChatHeader.textContent = groupLi.dataset.roomName;
        }
    } else {
        currentChatHeader.textContent = `${roomName.replace(username + '-', '').replace('-' + username, '')}`;
    }
    
    try {
        const response = await fetch(`/history/${roomName}?offset=0&limit=50`);
        const data = await response.json();
        
        if (currentRoom !== loadingRoomName) {
            isLoadingHistory = false;
            return;
        }
        
        chatMessagesDiv.innerHTML = '';
        
        if (data.error) {
            currentRoom = null;
            currentChatHeader.textContent = "Error loading chat.";
            callIcons.style.display = 'none';
            editGroupBtn.style.display = 'none';
            isLoadingHistory = false;
            return;
        }
        
        const usersInChat = [...new Set(data.messages.map(msg => msg.username))];
        await loadUserProfiles(usersInChat);
        
        data.messages.forEach(msg => addMessage(msg));
        messageOffset = data.messages.length;
        hasMoreMessages = data.has_more;
        scrollToBottom();
    } catch (error) {
        console.error("Error loading chat history:", error);
        if (currentRoom === loadingRoomName) {
            chatMessagesDiv.innerHTML = '';
            currentRoom = null;
            currentChatHeader.textContent = "Error loading chat.";
            callIcons.style.display = 'none';
            editGroupBtn.style.display = 'none';
        }
    } finally {
        isLoadingHistory = false;
    }
}

async function loadMoreMessages() {
    if (!currentRoom || isLoadingMore || !hasMoreMessages) return;
    
    isLoadingMore = true;
    const loadingDiv = document.createElement('div');
    loadingDiv.classList.add('loading-messages');
    loadingDiv.textContent = 'Loading more messages...';
    chatMessagesDiv.insertBefore(loadingDiv, chatMessagesDiv.firstChild);
    
    const scrollHeightBefore = chatMessagesDiv.scrollHeight;
    
    try {
        const response = await fetch(`/history/${currentRoom}?offset=${messageOffset}&limit=50`);
        const data = await response.json();
        
        if (data.error) {
            showOverlay(data.error);
            loadingDiv.remove();
            isLoadingMore = false;
            return;
        }
        
        loadingDiv.remove();
        
        if (data.messages && data.messages.length > 0) {
            const usersInMessages = [...new Set(data.messages.map(msg => msg.username))];
            await loadUserProfiles(usersInMessages);
            
            data.messages.forEach(msg => addMessage(msg, true));
            messageOffset += data.messages.length;
            hasMoreMessages = data.has_more;
            
            const scrollHeightAfter = chatMessagesDiv.scrollHeight;
            chatMessagesDiv.scrollTop = scrollHeightAfter - scrollHeightBefore;
        } else {
            hasMoreMessages = false;
        }
    } catch (error) {
        console.error("Error loading more messages:", error);
        loadingDiv.remove();
    } finally {
        isLoadingMore = false;
    }
}

async function loadUserProfiles(usernames) {
    try {
        const response = await fetch('/get_user_profiles', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ usernames })
        });
        const profiles = await response.json();
        userProfiles = { ...userProfiles, ...profiles };
        
        usernames.forEach(uname => {
            const avatarContainer = document.getElementById(`avatar-${uname}`);
            if (avatarContainer && profiles[uname] && profiles[uname].profile_picture) {
                avatarContainer.innerHTML = `<img src="${profiles[uname].profile_picture}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">`;
            }
        });
    } catch (error) {
        console.error('Error loading user profiles:', error);
    }
}

async function loadContactsWithTimestamps() {
    try {
        const response = await fetch('/get_contacts_order');
        const data = await response.json();
        
        if (data.contacts) {
            const orderMap = {};
            data.contacts.forEach((contact, index) => {
                orderMap[contact.id] = {
                    order: index,
                    unread_count: contact.unread_count || 0,
                    last_message_timestamp: contact.last_message_timestamp || 0,
                    last_message_text: contact.last_message_text || ''
                };
            });
            
            const items = Array.from(friendListUl.querySelectorAll('li'));
            items.sort((a, b) => {
                const aId = a.dataset.roomId || a.dataset.friendUsername;
                const bId = b.dataset.roomId || b.dataset.friendUsername;
                const aTimestamp = orderMap[aId] ? orderMap[aId].last_message_timestamp : 0;
                const bTimestamp = orderMap[bId] ? orderMap[bId].last_message_timestamp : 0;
                return bTimestamp - aTimestamp;
            });
            
            friendListUl.innerHTML = '';
            items.forEach(item => {
                const itemId = item.dataset.roomId || item.dataset.friendUsername;
                const contactData = orderMap[itemId];
                const existingIndicator = item.querySelector('.unread-indicator');
                if (existingIndicator) existingIndicator.remove();
                
                const storedUnreads = JSON.parse(localStorage.getItem('unreadCounts') || '{}');
                const storedCount = storedUnreads[itemId] || 0;
                const serverCount = contactData ? contactData.unread_count : 0;
                const finalCount = Math.max(storedCount, serverCount);
                
                if (finalCount > 0) {
                    const unreadBadge = document.createElement('span');
                    unreadBadge.classList.add('unread-indicator');
                    unreadBadge.textContent = finalCount;
                    item.querySelector('span').appendChild(unreadBadge);
                }
                
                const lastMsgPreview = item.querySelector('.last-message-preview');
                if (lastMsgPreview && contactData) {
                    const msgText = contactData.last_message_text || '';
                    const cleanText = stripHtmlForPreview(msgText);
                    lastMsgPreview.textContent = cleanText.substring(0, 40) + (cleanText.length > 40 ? '...' : '');
                }
                
                friendListUl.appendChild(item);
            });
        }
    } catch (error) {
        console.error('Error loading contact order:', error);
    }
}

function selectRoom(roomId, roomType, roomName, targetLi = null) {
    if (targetLi) {
        const unreadBadge = targetLi.querySelector('.unread-indicator');
        if (unreadBadge) {
            unreadBadge.remove();
            const storedUnreads = JSON.parse(localStorage.getItem('unreadCounts') || '{}');
            delete storedUnreads[roomId];
            localStorage.setItem('unreadCounts', JSON.stringify(storedUnreads));
        }
    }
    
    currentRoomType = roomType;
    const newRoomName = roomId;
    
    if (currentRoom) {
        socket.emit('leave', { room: currentRoom });
    }
    
    currentRoom = newRoomName;
    messageOffset = 0;
    hasMoreMessages = true;
    userScrolledUp = false;
    isAtBottom = true;
    
    socket.emit('join', { room: currentRoom });
    chatMessagesDiv.innerHTML = '<div class="loading-messages">Loading messages...</div>';
    
    Array.from(friendListUl.children).forEach(li => li.classList.remove('active'));
    if (targetLi) {
        targetLi.classList.add('active');
    }
    
    if (selectChatPrompt) {
        selectChatPrompt.style.display = 'none';
    }
    
    if (roomType === 'group') {
        editGroupBtn.style.display = 'inline';
        callIcons.style.display = 'none';
    } else {
        editGroupBtn.style.display = 'none';
        callIcons.style.display = 'flex';
    }
    
    cancelReply();
    loadChatHistory(newRoomName);
}

function selectFriend(friendUsername, targetLi = null) {
    if (targetLi) {
        const unreadBadge = targetLi.querySelector('.unread-indicator');
        if (unreadBadge) {
            unreadBadge.remove();
            const storedUnreads = JSON.parse(localStorage.getItem('unreadCounts') || '{}');
            const roomName = [username, friendUsername].sort().join('-');
            delete storedUnreads[roomName];
            localStorage.setItem('unreadCounts', JSON.stringify(storedUnreads));
        }
    }
    
    currentRoomType = 'direct';
    const newRoomName = [username, friendUsername].sort().join('-');
    
    if (currentRoom) {
        socket.emit('leave', { room: currentRoom });
    }
    
    currentRoom = newRoomName;
    messageOffset = 0;
    hasMoreMessages = true;
    userScrolledUp = false;
    isAtBottom = true;
    
    socket.emit('join', { room: currentRoom });
    chatMessagesDiv.innerHTML = '<div class="loading-messages">Loading messages...</div>';
    
    Array.from(friendListUl.children).forEach(li => li.classList.remove('active'));
    if (targetLi) {
        targetLi.classList.add('active');
    } else {
        const matchingLi = friendListUl.querySelector(`li[data-friend-username="${friendUsername}"]`);
        if (matchingLi) matchingLi.classList.add('active');
    }
    
    if (selectChatPrompt) {
        selectChatPrompt.style.display = 'none';
    }
    
    callIcons.style.display = 'flex';
    editGroupBtn.style.display = 'none';
    
    cancelReply();
    loadChatHistory(newRoomName);
}

friendListUl.addEventListener('click', (event) => {
    let targetLi = event.target.closest('li');
    if (targetLi && (targetLi.dataset.friendUsername || targetLi.dataset.roomId)) {
        if (targetLi.dataset.roomType === 'group') {
            const groupId = targetLi.dataset.roomId;
            const groupName = targetLi.dataset.roomName;
            localStorage.setItem('activeRoom', groupId);
            localStorage.setItem('activeRoomType', 'group');
            if (window.innerWidth < 768) {
                sidebar.classList.remove('active');
            }
            selectRoom(groupId, 'group', groupName, targetLi);
        } else {
            const friendUsername = targetLi.dataset.friendUsername;
            localStorage.setItem('activeFriend', friendUsername);
            localStorage.setItem('activeRoomType', 'direct');
            if (window.innerWidth < 768) {
                sidebar.classList.remove('active');
            }
            selectFriend(friendUsername, targetLi);
        }
    }
});

// ============================================
// GROUP MANAGEMENT
// ============================================

createGroupBtn.addEventListener('click', () => {
    groupModalTitle.textContent = 'Create New Group';
    createGroupForm.style.display = 'flex';
    editGroupForm.style.display = 'none';
    groupModal.classList.add('active');
    groupNameInput.value = '';
    document.querySelectorAll('#member-selection input[type="checkbox"]').forEach(cb => cb.checked = false);
});

cancelGroupBtn.addEventListener('click', () => {
    groupModal.classList.remove('active');
});

cancelEditGroupBtn.addEventListener('click', () => {
    groupModal.classList.remove('active');
    addMembersSection.style.display = 'none';
});

createGroupSubmit.addEventListener('click', async () => {
    const groupName = groupNameInput.value.trim();
    const selectedMembers = Array.from(document.querySelectorAll('#member-selection input[type="checkbox"]:checked'))
        .map(cb => cb.value);
    
    if (!groupName) {
        showOverlay('Please enter a group name');
        return;
    }
    
    if (selectedMembers.length < 2) {
        showOverlay('Please select at least 2 members');
        return;
    }
    
    try {
        const response = await fetch('/create_group', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                name: groupName,
                members: selectedMembers
            })
        });
        
        const data = await response.json();
        
        if (data.error) {
            showOverlay(data.error);
        } else {
            groupModal.classList.remove('active');
            const groupLi = document.createElement('li');
            groupLi.setAttribute('data-room-id', data.group_id);
            groupLi.setAttribute('data-room-type', 'group');
            groupLi.setAttribute('data-room-name', data.group_name);
            groupLi.innerHTML = `
                <div class="friend-avatar" style="background: var(--primary);">
                    <i class="fas fa-users"></i>
                </div>
                <span>${data.group_name} <span class="group-indicator">GROUP</span></span>
            `;
            friendListUl.insertBefore(groupLi, friendListUl.firstChild);
            showOverlay('Group created successfully!');
        }
    } catch (error) {
        console.error('Error creating group:', error);
        showOverlay('Failed to create group');
    }
});

// ============================================
// MEDIA AND FILE HANDLING
// ============================================

messageInput.addEventListener('paste', async (e) => {
    const items = e.clipboardData.items;
    for (let i = 0; i < items.length; i++) {
        if (items[i].type.indexOf('image') !== -1 || items[i].type.indexOf('video') !== -1) {
            e.preventDefault();
            const blob = items[i].getAsFile();
            showMediaPreview(blob);
            break;
        }
    }
});

document.addEventListener('paste', async (e) => {
    if (document.activeElement !== messageInput) return;
    const items = e.clipboardData.items;
    for (let i = 0; i < items.length; i++) {
        if (items[i].type.indexOf('image') !== -1 || items[i].type.indexOf('video') !== -1) {
            e.preventDefault();
            const blob = items[i].getAsFile();
            showMediaPreview(blob);
            break;
        }
    }
});

function showMediaPreview(file) {
    if (!currentRoom) {
        showOverlay("Please select a friend or group to chat with first.");
        return;
    }
    
    pendingMediaFile = file;
    mediaPreviewContainer.innerHTML = '';
    
    const fileExtension = file.name ? file.name.split('.').pop().toLowerCase() : file.type.split('/')[1];
    const isVideo = file.type.startsWith('video/') || ['mp4', 'webm', 'ogg'].includes(fileExtension);
    
    if (isVideo) {
        const video = document.createElement('video');
        video.controls = true;
        video.src = URL.createObjectURL(file);
        mediaPreviewContainer.appendChild(video);
    } else {
        const img = document.createElement('img');
        img.src = URL.createObjectURL(file);
        mediaPreviewContainer.appendChild(img);
    }
    
    mediaPreviewModal.classList.add('active');
}

sendMediaBtn.addEventListener('click', async () => {
    if (!pendingMediaFile) return;
    
    mediaPreviewModal.classList.remove('active');
    const formData = new FormData();
    formData.append('file', pendingMediaFile);
    
    try {
        const response = await fetch('/upload_file', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.error) {
            showOverlay(`File upload failed: ${data.error}`);
        } else if (data.url) {
            const fileName = pendingMediaFile.name || 'file';
            const fileExtension = fileName.split('.').pop().toLowerCase();
            let messageContent;
            
            if (['png', 'jpg', 'jpeg', 'gif'].includes(fileExtension)) {
                messageContent = `<a href="${data.url}" target="_blank"><img src="${data.url}" class="message-file image" alt="Uploaded Image"></a>`;
            } else if (['mp4', 'webm', 'ogg'].includes(fileExtension)) {
                messageContent = `<video controls src="${data.url}" class="message-file video"></video>`;
            } else {
                messageContent = `<a href="${data.url}" target="_blank">Uploaded file: ${fileName}</a>`;
            }
            
            const messageData = {
                username: username,
                room: currentRoom,
                msg: messageContent
            };
            
            if (replyingTo) {
                messageData.reply_to = replyingTo;
            }
            
            socket.emit('send_message', messageData);
            messageInput.focus();
            cancelReply();
        }
    } catch (error) {
        console.error("Error uploading file:", error);
        showOverlay("An error occurred during file upload.");
    } finally {
        pendingMediaFile = null;
    }
});

cancelMediaBtn.addEventListener('click', () => {
    mediaPreviewModal.classList.remove('active');
    pendingMediaFile = null;
    mediaPreviewContainer.innerHTML = '';
});

fileInput.addEventListener('change', async (event) => {
    if (!currentRoom) {
        showOverlay("Please select a friend or group to chat with first.");
        fileInput.value = '';
        return;
    }
    
    const file = event.target.files[0];
    if (!file) return;
    
    showMediaPreview(file);
    fileInput.value = '';
});

// ============================================
// SOCKET EVENT HANDLERS
// ============================================

socket.on('message', (data) => {
    if (chatMessagesDiv.querySelector(`[data-message-id="${data.id}"]`)) {
        return;
    }
    
    if (!userProfiles[data.username]) {
        loadUserProfiles([data.username]);
    }
    
    const isOwnMessage = data.username === username;
    
    let chatName = '';
    if (data.room.startsWith('group_')) {
        const groupLi = friendListUl.querySelector(`li[data-room-id="${data.room}"]`);
        chatName = groupLi ? groupLi.dataset.roomName : 'Group Chat';
    } else {
        chatName = data.room.replace(username + '-', '').replace('-' + username, '');
    }
    
    if (data.room === currentRoom) {
        addMessage(data);
        if (isAtBottom) {
            scrollToBottom();
        }
        
        if (!isOwnMessage) {
            showNotificationAndPlaySound(
                `${data.username} (${chatName})`,
                stripHtmlForPreview(data.msg),
                data.room
            );
        }
    } else {
        if (!isOwnMessage) {
            let contactLi;
            let roomIdOrName;
            
            if (data.room.startsWith('group_')) {
                contactLi = friendListUl.querySelector(`li[data-room-id="${data.room}"]`);
                roomIdOrName = data.room;
            } else {
                const otherUser = data.room.replace(username + '-', '').replace('-' + username, '');
                contactLi = friendListUl.querySelector(`li[data-friend-username="${otherUser}"]`);
                roomIdOrName = data.room;
            }
            
            if (contactLi) {
                friendListUl.removeChild(contactLi);
                friendListUl.insertBefore(contactLi, friendListUl.firstChild);
                
                let storedUnreads = JSON.parse(localStorage.getItem('unreadCounts') || '{}');
                const currentCount = storedUnreads[roomIdOrName] || 0;
                const newCount = currentCount + 1;
                storedUnreads[roomIdOrName] = newCount;
                localStorage.setItem('unreadCounts', JSON.stringify(storedUnreads));
                
                let unreadBadge = contactLi.querySelector('.unread-indicator');
                if (!unreadBadge) {
                    unreadBadge = document.createElement('span');
                    unreadBadge.classList.add('unread-indicator');
                    unreadBadge.textContent = newCount.toString();
                    const mainSpan = contactLi.querySelector('span');
                    if (mainSpan) {
                        mainSpan.appendChild(unreadBadge);
                    }
                } else {
                    unreadBadge.textContent = newCount.toString();
                }
                
                const lastMsgPreview = contactLi.querySelector('.last-message-preview');
                if (lastMsgPreview) {
                    const cleanText = stripHtmlForPreview(data.msg);
                    lastMsgPreview.textContent = cleanText.substring(0, 40) + (cleanText.length > 40 ? '...' : '');
                }
                
                showNotificationAndPlaySound(
                    `${data.username} (${chatName})`,
                    stripHtmlForPreview(data.msg),
                    data.room
                );
            }
        }
    }
    
    loadContactsWithTimestamps();
});

socket.on('message_updated', (data) => {
    if (data.room === currentRoom) {
        const newTextWithEditedTag = data.new_text.includes("<em>(edited)</em>")
                                    ? data.new_text
                                    : `${data.new_text} <em>(edited)</em>`;
        updateMessage(data.id, newTextWithEditedTag);
    }
});

socket.on('error', (data) => {
    console.error('Socket Error:', data.message);
    if (data.message.includes('not friends') || data.message.includes('blocked') || 
        data.message.includes('Unauthorized') || data.message.includes('not a member')) {
        currentRoom = null;
        chatMessagesDiv.innerHTML = '';
        currentChatHeader.textContent = "";
        callIcons.style.display = 'none';
        editGroupBtn.style.display = 'none';
        if (selectChatPrompt) {
            selectChatPrompt.style.display = 'block';
            selectChatPrompt.textContent = "Select a friend or group from the sidebar to start chatting.";
        }
    } else {
        showOverlay(data.message);
    }
});

socket.on('user_status_update', (data) => {
    const statusIndicator = document.querySelector(`.status-indicator[data-username="${data.username}"]`);
    if (statusIndicator) {
        statusIndicator.className = 'status-indicator';
        statusIndicator.classList.add(data.status);
    }
    connectedUsers[data.username] = data.status;
});

socket.on('user_typing', (data) => {
    const typingIndicator = document.getElementById('typing-indicator');
    if (data.is_typing) {
        if (!typingIndicator) {
            const indicator = document.createElement('div');
            indicator.id = 'typing-indicator';
            indicator.className = 'typing-indicator';
            indicator.innerHTML = `
                <span>${data.username}</span>
                <span>is typing</span>
                <span>...</span>
            `;
            chatMessagesDiv.appendChild(indicator);
            if (isAtBottom) {
                scrollToBottom();
            }
        }
    } else {
        const existingIndicator = document.getElementById('typing-indicator');
        if (existingIndicator) {
            existingIndicator.remove();
        }
    }
});

socket.on('all_statuses', (data) => {
    Object.keys(data).forEach(username => {
        const statusIndicator = document.querySelector(`.status-indicator[data-username="${username}"]`);
        if (statusIndicator) {
            statusIndicator.className = 'status-indicator';
            statusIndicator.classList.add(data[username].status);
        }
    });
});

// ============================================
// MOBILE KEYBOARD HANDLING
// ============================================

const chatArea = document.querySelector('.chat-area');
let isAboutToSend = false;

function handleMobileFocus() {
    if (window.innerWidth > 768) return;
    chatArea.style.paddingBottom = '20vh';
    setTimeout(() => {
        messageInput.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 150);
}

function handleMobileBlur() {
    if (window.innerWidth <= 768) {
        setTimeout(() => {
            if (!isAboutToSend) {
                chatArea.style.paddingBottom = '0';
            }
            isAboutToSend = false;
        }, 300);
    }
}

sendButton.addEventListener('mousedown', () => isAboutToSend = true);
sendButton.addEventListener('touchstart', () => isAboutToSend = true);
messageInput.addEventListener('focus', handleMobileFocus);
messageInput.addEventListener('blur', handleMobileBlur);