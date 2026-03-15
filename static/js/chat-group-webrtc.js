/**
 * chat-group-webrtc.js
 * Mesh WebRTC for Kryonix group calls.
 * Each participant creates a peer connection to every other participant (full mesh).
 */

(function () {
    'use strict';

    // ── State ────────────────────────────────────────────────────────────────
    const groupCall = {
        active: false,
        callRoom: null,
        groupRoom: null,
        callType: null,          // 'video' | 'audio'
        localStream: null,
        peers: {},               // { username: RTCPeerConnection }
        audioMuted: false,
        videoMuted: false,
        screenSharing: false,
        screenStream: null,
        pendingIncoming: null,   // { call_room, room, group_name, started_by, type }
    };

    const ICE_SERVERS = {
        iceServers: [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' }
        ]
    };

    // ── DOM References ────────────────────────────────────────────────────────
    const groupCallModal       = document.getElementById('group-call-modal');
    const incomingGroupModal   = document.getElementById('incoming-group-call-modal');
    const groupVideoGrid       = document.getElementById('group-video-grid');
    const localGroupVideo      = document.getElementById('local-group-video');
    const groupCallTitle       = document.getElementById('group-call-title');
    const groupCallStatus      = document.getElementById('group-call-status');

    // Buttons
    const groupAudioCallBtn    = document.getElementById('group-audio-call-btn');
    const groupVideoCallBtn    = document.getElementById('group-video-call-btn');
    const groupMuteAudioBtn    = document.getElementById('group-mute-audio-btn');
    const groupMuteVideoBtn    = document.getElementById('group-mute-video-btn');
    const groupShareScreenBtn  = document.getElementById('group-share-screen-btn');
    const groupEndCallBtn      = document.getElementById('group-end-call-btn');
    const minimizeGroupCallBtn = document.getElementById('minimize-group-call-btn');
    const answerGroupCallBtn   = document.getElementById('answer-group-call-btn');
    const rejectGroupCallBtn   = document.getElementById('reject-group-call-btn');
    const groupCallGroupName   = document.getElementById('group-call-group-name');
    const groupCallerName      = document.getElementById('group-caller-name');
    const groupCallTypeText    = document.getElementById('group-call-type-text');

    // ── Socket (reuse window.socket set by chat-main.js) ─────────────────────
    function getSocket() {
        return window.socket;
    }

    // ── Call Initiation ───────────────────────────────────────────────────────
    async function startGroupCall(groupRoomId, callType) {
        if (groupCall.active) {
            showGroupCallStatus('You are already in a call.');
            return;
        }
        groupCall.callType = callType;
        groupCall.groupRoom = groupRoomId;

        try {
            groupCall.localStream = await getMedia(callType);
        } catch (err) {
            alert('Could not access camera/microphone: ' + err.message);
            return;
        }

        localGroupVideo.srcObject = groupCall.localStream;
        showGroupCallModal(callType);
        groupCallStatus.textContent = 'Starting call…';

        getSocket().emit('group_call_start', {
            room: groupRoomId,
            type: callType
        });
    }

    // ── Media Helpers ─────────────────────────────────────────────────────────
    function getMedia(callType) {
        const constraints = callType === 'video'
            ? { audio: true, video: { width: 1280, height: 720 } }
            : { audio: true, video: false };
        return navigator.mediaDevices.getUserMedia(constraints);
    }

    // ── Show / Hide Modals ────────────────────────────────────────────────────
    function showGroupCallModal(callType) {
        groupCall.active = true;
        groupCallModal.style.display = 'flex';
        groupCallTitle.innerHTML = callType === 'video'
            ? '<i class="fas fa-video"></i> Group Video Call'
            : '<i class="fas fa-phone"></i> Group Audio Call';
        if (callType === 'audio') {
            document.getElementById('local-group-tile').classList.add('audio-only');
            localGroupVideo.style.display = 'none';
            document.getElementById('local-group-tile').insertAdjacentHTML(
                'afterbegin', '<div class="avatar-placeholder">' + (window.currentUsername || 'Me')[0] + '</div>'
            );
        }
    }

    function hideGroupCallModal() {
        groupCallModal.style.display = 'none';
        incomingGroupModal.style.display = 'none';
    }

    // ── Peer Connection Management ────────────────────────────────────────────
    function createPeerConnection(remoteUsername, isOfferer) {
        const pc = new RTCPeerConnection(ICE_SERVERS);
        groupCall.peers[remoteUsername] = pc;

        // Add local tracks
        if (groupCall.localStream) {
            groupCall.localStream.getTracks().forEach(track => {
                pc.addTrack(track, groupCall.localStream);
            });
        }

        // ICE candidates
        pc.onicecandidate = (evt) => {
            if (evt.candidate) {
                getSocket().emit('group_webrtc_ice', {
                    call_room: groupCall.callRoom,
                    target: remoteUsername,
                    candidate: evt.candidate
                });
            }
        };

        // Remote stream → create video tile
        const remoteStream = new MediaStream();
        pc.ontrack = (evt) => {
            evt.streams[0].getTracks().forEach(track => remoteStream.addTrack(track));
            getOrCreateVideoTile(remoteUsername, remoteStream);
        };

        pc.onconnectionstatechange = () => {
            if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed' || pc.connectionState === 'closed') {
                removeVideoTile(remoteUsername);
                delete groupCall.peers[remoteUsername];
                updateParticipantCount();
            }
        };

        if (isOfferer) {
            pc.onnegotiationneeded = async () => {
                try {
                    const offer = await pc.createOffer();
                    await pc.setLocalDescription(offer);
                    getSocket().emit('group_webrtc_offer', {
                        call_room: groupCall.callRoom,
                        target: remoteUsername,
                        offer: pc.localDescription
                    });
                } catch (e) {
                    console.error('Offer error:', e);
                }
            };
        }

        return pc;
    }

    // ── Video Tile Helpers ────────────────────────────────────────────────────
    function getOrCreateVideoTile(username, stream) {
        let tile = document.getElementById('tile-' + username);
        if (!tile) {
            tile = document.createElement('div');
            tile.className = 'group-video-tile';
            tile.id = 'tile-' + username;

            const video = document.createElement('video');
            video.autoplay = true;
            video.playsInline = true;
            video.id = 'video-' + username;

            const label = document.createElement('div');
            label.className = 'video-tile-label';
            label.textContent = username;

            tile.appendChild(video);
            tile.appendChild(label);
            groupVideoGrid.appendChild(tile);
        }
        const vid = document.getElementById('video-' + username);
        if (vid) vid.srcObject = stream;
        return tile;
    }

    function removeVideoTile(username) {
        const tile = document.getElementById('tile-' + username);
        if (tile) tile.remove();
    }

    function updateParticipantCount() {
        const count = Object.keys(groupCall.peers).length + 1; // +1 for self
        groupCallStatus.textContent = count + ' participant' + (count !== 1 ? 's' : '');
    }

    // ── Hang Up / Leave ───────────────────────────────────────────────────────
    function leaveGroupCall() {
        if (!groupCall.active) return;

        // Close all peers
        Object.values(groupCall.peers).forEach(pc => pc.close());
        groupCall.peers = {};

        // Stop local stream
        if (groupCall.localStream) {
            groupCall.localStream.getTracks().forEach(t => t.stop());
            groupCall.localStream = null;
        }
        if (groupCall.screenStream) {
            groupCall.screenStream.getTracks().forEach(t => t.stop());
            groupCall.screenStream = null;
        }

        getSocket().emit('group_call_leave', { call_room: groupCall.callRoom });

        // Reset state
        groupCall.active = false;
        groupCall.callRoom = null;
        groupCall.audioMuted = false;
        groupCall.videoMuted = false;
        groupCall.screenSharing = false;

        // Clear grid (keep local tile template)
        Array.from(groupVideoGrid.querySelectorAll('.group-video-tile:not(#local-group-tile)')).forEach(t => t.remove());
        localGroupVideo.srcObject = null;
        // Re-show video element in case it was hidden
        localGroupVideo.style.display = '';
        document.getElementById('local-group-tile').classList.remove('audio-only');
        const avatarPlaceholder = document.getElementById('local-group-tile').querySelector('.avatar-placeholder');
        if (avatarPlaceholder) avatarPlaceholder.remove();

        hideGroupCallModal();
    }

    // ── Mute / Video Toggle ───────────────────────────────────────────────────
    function toggleGroupAudio() {
        if (!groupCall.localStream) return;
        groupCall.audioMuted = !groupCall.audioMuted;
        groupCall.localStream.getAudioTracks().forEach(t => { t.enabled = !groupCall.audioMuted; });
        groupMuteAudioBtn.innerHTML = groupCall.audioMuted
            ? '<i class="fas fa-microphone-slash"></i>'
            : '<i class="fas fa-microphone"></i>';
        groupMuteAudioBtn.style.background = groupCall.audioMuted ? 'var(--danger)' : '';
    }

    function toggleGroupVideo() {
        if (!groupCall.localStream) return;
        groupCall.videoMuted = !groupCall.videoMuted;
        groupCall.localStream.getVideoTracks().forEach(t => { t.enabled = !groupCall.videoMuted; });
        groupMuteVideoBtn.innerHTML = groupCall.videoMuted
            ? '<i class="fas fa-video-slash"></i>'
            : '<i class="fas fa-video"></i>';
        groupMuteVideoBtn.style.background = groupCall.videoMuted ? 'var(--danger)' : '';
    }

    async function toggleGroupScreenShare() {
        if (!groupCall.active) return;
        if (groupCall.screenSharing) {
            // Stop screen share, revert to camera
            groupCall.screenStream.getTracks().forEach(t => t.stop());
            groupCall.screenStream = null;
            groupCall.screenSharing = false;

            const cameraTrack = groupCall.localStream.getVideoTracks()[0];
            if (cameraTrack) {
                Object.values(groupCall.peers).forEach(pc => {
                    const sender = pc.getSenders().find(s => s.track && s.track.kind === 'video');
                    if (sender) sender.replaceTrack(cameraTrack);
                });
            }
            groupShareScreenBtn.classList.remove('active');
            groupShareScreenBtn.title = 'Share Screen';
        } else {
            try {
                groupCall.screenStream = await navigator.mediaDevices.getDisplayMedia({ video: true });
                const screenTrack = groupCall.screenStream.getVideoTracks()[0];
                groupCall.screenSharing = true;

                Object.values(groupCall.peers).forEach(pc => {
                    const sender = pc.getSenders().find(s => s.track && s.track.kind === 'video');
                    if (sender) sender.replaceTrack(screenTrack);
                });

                // Update local preview
                const localStream = new MediaStream([screenTrack, ...groupCall.localStream.getAudioTracks()]);
                localGroupVideo.srcObject = localStream;

                screenTrack.onended = () => toggleGroupScreenShare();

                groupShareScreenBtn.classList.add('active');
                groupShareScreenBtn.title = 'Stop Sharing';
            } catch (e) {
                console.warn('Screen share cancelled or error:', e);
            }
        }
    }

    // ── Socket Event Handlers ─────────────────────────────────────────────────
    function bindSocketEvents() {
        const socket = getSocket();
        if (!socket) {
            // socket may not be ready yet — retry
            setTimeout(bindSocketEvents, 300);
            return;
        }

        // Successfully joined a group call — server tells us existing participants
        socket.on('group_call_joined', async (data) => {
            groupCall.callRoom = data.call_room;
            groupCall.callType = data.type;
            groupCallStatus.textContent = 'Connected';

            // Create peer connections to everyone already in the call (we are the offerer)
            for (const participant of data.existing_participants) {
                const pc = createPeerConnection(participant, true);
                // Negotiation needed will fire and send offer
            }
            updateParticipantCount();
        });

        // A new user joined — we are NOT the offerer (they will send us an offer)
        socket.on('group_call_user_joined', (data) => {
            groupCallStatus.textContent = 'Connected';
            updateParticipantCount();
            // Peer will send us an offer via group_webrtc_offer; just prepare PC
            if (!groupCall.peers[data.username]) {
                createPeerConnection(data.username, false);
            }
        });

        // Someone left the call
        socket.on('group_call_user_left', (data) => {
            removeVideoTile(data.username);
            if (groupCall.peers[data.username]) {
                groupCall.peers[data.username].close();
                delete groupCall.peers[data.username];
            }
            updateParticipantCount();
        });

        // Incoming group call notification
        socket.on('incoming_group_call', (data) => {
            groupCall.pendingIncoming = data;
            groupCallGroupName.textContent = data.group_name;
            groupCallerName.textContent = data.started_by + ' started a call' +
                (data.participant_count > 1 ? ' (' + data.participant_count + ' in call)' : '');
            groupCallTypeText.textContent = data.type === 'video' ? 'Video Call' : 'Audio Call';
            incomingGroupModal.style.display = 'flex';
        });

        // Receive WebRTC offer from a peer
        socket.on('group_webrtc_offer', async (data) => {
            const { offer, sender, call_room } = data;
            if (call_room !== groupCall.callRoom) return;

            let pc = groupCall.peers[sender];
            if (!pc) {
                pc = createPeerConnection(sender, false);
            }
            await pc.setRemoteDescription(new RTCSessionDescription(offer));
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            socket.emit('group_webrtc_answer', {
                call_room: groupCall.callRoom,
                target: sender,
                answer: pc.localDescription
            });
        });

        // Receive WebRTC answer
        socket.on('group_webrtc_answer', async (data) => {
            const { answer, sender, call_room } = data;
            if (call_room !== groupCall.callRoom) return;
            const pc = groupCall.peers[sender];
            if (pc && pc.signalingState !== 'stable') {
                await pc.setRemoteDescription(new RTCSessionDescription(answer));
            }
        });

        // Receive ICE candidate
        socket.on('group_webrtc_ice', async (data) => {
            const { candidate, sender, call_room } = data;
            if (call_room !== groupCall.callRoom) return;
            const pc = groupCall.peers[sender];
            if (pc && candidate) {
                try {
                    await pc.addIceCandidate(new RTCIceCandidate(candidate));
                } catch (e) {
                    console.warn('ICE error:', e);
                }
            }
        });
    }

    // ── Button Event Listeners ────────────────────────────────────────────────
    // These are set up after DOM ready
    function bindButtons() {
        // Header call buttons (shown when group chat selected)
        if (groupAudioCallBtn) {
            groupAudioCallBtn.addEventListener('click', () => {
                const room = window.currentGroupRoom;
                if (room) startGroupCall(room, 'audio');
            });
        }
        if (groupVideoCallBtn) {
            groupVideoCallBtn.addEventListener('click', () => {
                const room = window.currentGroupRoom;
                if (room) startGroupCall(room, 'video');
            });
        }

        // In-call controls
        if (groupMuteAudioBtn) groupMuteAudioBtn.addEventListener('click', toggleGroupAudio);
        if (groupMuteVideoBtn) groupMuteVideoBtn.addEventListener('click', toggleGroupVideo);
        if (groupShareScreenBtn) groupShareScreenBtn.addEventListener('click', toggleGroupScreenShare);
        if (groupEndCallBtn) groupEndCallBtn.addEventListener('click', leaveGroupCall);

        if (minimizeGroupCallBtn) {
            minimizeGroupCallBtn.addEventListener('click', () => {
                groupCallModal.style.display = 'none';
            });
        }

        // Incoming call answer/reject
        if (answerGroupCallBtn) {
            answerGroupCallBtn.addEventListener('click', async () => {
                const incoming = groupCall.pendingIncoming;
                if (!incoming) return;
                incomingGroupModal.style.display = 'none';

                groupCall.callRoom = incoming.call_room;
                groupCall.groupRoom = incoming.room;
                groupCall.callType = incoming.type;

                try {
                    groupCall.localStream = await getMedia(incoming.type);
                } catch (err) {
                    alert('Could not access camera/microphone: ' + err.message);
                    return;
                }

                localGroupVideo.srcObject = groupCall.localStream;
                showGroupCallModal(incoming.type);
                groupCallStatus.textContent = 'Joining…';

                getSocket().emit('group_call_start', {
                    room: incoming.room,
                    type: incoming.type
                });

                groupCall.pendingIncoming = null;
            });
        }

        if (rejectGroupCallBtn) {
            rejectGroupCallBtn.addEventListener('click', () => {
                const incoming = groupCall.pendingIncoming;
                if (incoming) {
                    getSocket().emit('group_call_reject', { call_room: incoming.call_room });
                }
                incomingGroupModal.style.display = 'none';
                groupCall.pendingIncoming = null;
            });
        }
    }

    // ── Integration with chat-main.js ─────────────────────────────────────────
    // chat-main.js sets window.currentRoom and shows/hides call-icons.
    // We hook into contact selection to show group-call-icons instead.
    function hookIntoContactSelection() {
        // Patch: watch for chat-main.js activating a group room
        // chat-main.js sets window.currentRoom; we observe via MutationObserver on header
        const chatHeader = document.getElementById('current-chat-header');
        if (!chatHeader) return;

        const regularCallIcons = document.getElementById('call-icons');
        const groupCallIcons   = document.getElementById('group-call-icons');

        if (!regularCallIcons || !groupCallIcons) return;

        // Override the header update logic: patch window after each contact click
        document.querySelectorAll('#friend-list-ul li').forEach(li => {
            li.addEventListener('click', () => {
                const roomType = li.dataset.roomType;
                const roomId   = li.dataset.roomId;

                if (roomType === 'group') {
                    window.currentGroupRoom = roomId;
                    regularCallIcons.style.display = 'none';
                    groupCallIcons.style.display = 'flex';
                } else {
                    window.currentGroupRoom = null;
                    groupCallIcons.style.display = 'none';
                    // regular call icons shown by chat-main.js
                }
            });
        });
    }

    // ── Init ──────────────────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', () => {
        bindButtons();
        hookIntoContactSelection();
        // Bind socket events after a short delay to let chat-main.js init socket
        setTimeout(bindSocketEvents, 500);
    });

    // Expose for console debugging
    window.groupCall = groupCall;
    window.startGroupCall = startGroupCall;
    window.leaveGroupCall = leaveGroupCall;

}());
