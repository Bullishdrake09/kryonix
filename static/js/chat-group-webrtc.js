/**
 * chat-group-webrtc.js  —  full-mesh group calls for Kryonix
 *
 * Requires:  window.socket  (set by chat-main.js before this file loads)
 *            window.username
 *            window.currentGroupRoom  (set by chat-main.js when a group is selected)
 */

(function () {
    'use strict';

    const ICE_CONFIG = {
        iceServers: [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' }
        ]
    };

    // ── State ─────────────────────────────────────────────────────────────────
    const gc = {
        active:        false,
        callRoom:      null,   // socket room for WebRTC signalling
        groupRoom:     null,   // actual group chat room id
        callType:      null,
        localStream:   null,
        screenStream:  null,
        screenSharing: false,
        audioMuted:    false,
        videoMuted:    false,
        peers:         {},     // { username: RTCPeerConnection }
        pendingIncoming: null,
    };

    // ── DOM ───────────────────────────────────────────────────────────────────
    const els = {
        modal:          document.getElementById('group-call-modal'),
        incomingModal:  document.getElementById('incoming-group-call-modal'),
        grid:           document.getElementById('group-video-grid'),
        localVideo:     document.getElementById('local-group-video'),
        title:          document.getElementById('group-call-title'),
        status:         document.getElementById('group-call-status'),
        groupName:      document.getElementById('group-call-group-name'),
        callerName:     document.getElementById('group-caller-name'),
        callTypeText:   document.getElementById('group-call-type-text'),
        audioBtnHeader: document.getElementById('group-audio-call-btn'),
        videoBtnHeader: document.getElementById('group-video-call-btn'),
        muteAudio:      document.getElementById('group-mute-audio-btn'),
        muteVideo:      document.getElementById('group-mute-video-btn'),
        shareScreen:    document.getElementById('group-share-screen-btn'),
        endCall:        document.getElementById('group-end-call-btn'),
        minimize:       document.getElementById('minimize-group-call-btn'),
        answer:         document.getElementById('answer-group-call-btn'),
        reject:         document.getElementById('reject-group-call-btn'),
    };

    function sock()  { return window.socket; }
    function myName(){ return window.username || document.querySelector('.username').textContent.trim(); }

    // ── Media ─────────────────────────────────────────────────────────────────
    function getMedia(type) {
        return navigator.mediaDevices.getUserMedia(
            type === 'video'
                ? { audio: { echoCancellation: true }, video: { width: { ideal: 1280 }, height: { ideal: 720 } } }
                : { audio: { echoCancellation: true }, video: false }
        );
    }

    // ── Peer connection factory ───────────────────────────────────────────────
    function createPeer(remoteUser, isOfferer) {
        // Close stale connection
        if (gc.peers[remoteUser]) {
            gc.peers[remoteUser].close();
            delete gc.peers[remoteUser];
        }

        const pc = new RTCPeerConnection(ICE_CONFIG);
        gc.peers[remoteUser] = pc;

        if (gc.localStream) {
            gc.localStream.getTracks().forEach(t => pc.addTrack(t, gc.localStream));
        }

        const remoteStream = new MediaStream();
        pc.ontrack = evt => {
            evt.streams[0].getTracks().forEach(t => remoteStream.addTrack(t));
            getOrMakeTile(remoteUser).querySelector('video').srcObject = remoteStream;
            getOrMakeTile(remoteUser).classList.toggle('audio-only', gc.callType === 'audio');
        };

        pc.onicecandidate = evt => {
            if (evt.candidate) {
                sock().emit('group_webrtc_ice', {
                    call_room: gc.callRoom,
                    target:    remoteUser,
                    candidate: evt.candidate
                });
            }
        };

        pc.onconnectionstatechange = () => {
            if (['disconnected', 'failed', 'closed'].includes(pc.connectionState)) {
                removeTile(remoteUser);
                if (gc.peers[remoteUser] === pc) delete gc.peers[remoteUser];
                updateCount();
            }
        };

        if (isOfferer) {
            pc.onnegotiationneeded = async () => {
                try {
                    const offer = await pc.createOffer();
                    await pc.setLocalDescription(offer);
                    sock().emit('group_webrtc_offer', {
                        call_room: gc.callRoom,
                        target:    remoteUser,
                        offer:     pc.localDescription
                    });
                } catch (e) { console.error('Group offer error:', e); }
            };
        }

        return pc;
    }

    // ── Video grid helpers ────────────────────────────────────────────────────
    function getOrMakeTile(user) {
        let tile = document.getElementById('gtile-' + user);
        if (!tile) {
            tile = document.createElement('div');
            tile.className = 'group-video-tile';
            tile.id = 'gtile-' + user;

            const v = document.createElement('video');
            v.autoplay = true; v.playsInline = true;

            const label = document.createElement('div');
            label.className = 'video-tile-label';
            label.textContent = user;

            tile.appendChild(v);
            tile.appendChild(label);
            if (els.grid) els.grid.appendChild(tile);
        }
        return tile;
    }

    function removeTile(user) {
        const t = document.getElementById('gtile-' + user);
        if (t) t.remove();
    }

    function updateCount() {
        const n = Object.keys(gc.peers).length + 1;
        if (els.status) els.status.textContent = `${n} participant${n !== 1 ? 's' : ''}`;
    }

    // ── Show / hide modals ────────────────────────────────────────────────────
    function showModal(type) {
        gc.active = true;
        if (!els.modal) return;
        els.modal.style.display = 'flex';
        if (els.title) els.title.innerHTML = type === 'video'
            ? '<i class="fas fa-video"></i> Group Video Call'
            : '<i class="fas fa-phone"></i> Group Audio Call';

        const localTile = document.getElementById('local-group-tile');
        if (type === 'audio' && localTile) {
            localTile.classList.add('audio-only');
            if (els.localVideo) els.localVideo.style.display = 'none';
            if (!localTile.querySelector('.avatar-placeholder')) {
                const ph = document.createElement('div');
                ph.className = 'avatar-placeholder';
                ph.textContent = (myName()[0] || '?').toUpperCase();
                localTile.insertBefore(ph, localTile.firstChild);
            }
        } else if (localTile) {
            localTile.classList.remove('audio-only');
            if (els.localVideo) els.localVideo.style.display = '';
            const ph = localTile.querySelector('.avatar-placeholder');
            if (ph) ph.remove();
        }
        if (els.muteVideo) els.muteVideo.style.display = type === 'video' ? '' : 'none';
        if (els.shareScreen) els.shareScreen.style.display = type === 'video' ? '' : 'none';
    }

    function hideModal() {
        if (els.modal)         els.modal.style.display         = 'none';
        if (els.incomingModal) els.incomingModal.style.display = 'none';
    }

    // ── Start / join call ─────────────────────────────────────────────────────
    async function startCall(groupRoomId, type) {
        if (gc.active) return;
        gc.callType  = type;
        gc.groupRoom = groupRoomId;

        try {
            gc.localStream = await getMedia(type);
        } catch (err) {
            if (typeof window.showOverlay === 'function')
                window.showOverlay('Could not access camera/microphone: ' + err.message);
            return;
        }

        if (els.localVideo) els.localVideo.srcObject = gc.localStream;
        showModal(type);
        if (els.status) els.status.textContent = 'Starting…';

        sock().emit('group_call_start', { room: groupRoomId, type });
    }

    // ── Leave call ────────────────────────────────────────────────────────────
    function leaveCall() {
        if (!gc.active) return;

        Object.values(gc.peers).forEach(pc => pc.close());
        gc.peers = {};

        [gc.localStream, gc.screenStream].forEach(s => {
            if (s) s.getTracks().forEach(t => t.stop());
        });

        sock().emit('group_call_leave', { call_room: gc.callRoom });

        // Reset DOM
        const localTile = document.getElementById('local-group-tile');
        if (localTile) {
            localTile.classList.remove('audio-only');
            const ph = localTile.querySelector('.avatar-placeholder');
            if (ph) ph.remove();
        }
        if (els.localVideo) { els.localVideo.srcObject = null; els.localVideo.style.display = ''; }
        // Remove all remote tiles
        if (els.grid) {
            Array.from(els.grid.querySelectorAll('.group-video-tile:not(#local-group-tile)'))
                .forEach(t => t.remove());
        }

        // Reset button icons
        if (els.muteAudio) { els.muteAudio.innerHTML = '<i class="fas fa-microphone"></i>'; els.muteAudio.style.background = ''; }
        if (els.muteVideo) { els.muteVideo.innerHTML = '<i class="fas fa-video"></i>';       els.muteVideo.style.background = ''; }
        if (els.shareScreen) els.shareScreen.classList.remove('active');

        Object.assign(gc, {
            active: false, callRoom: null, localStream: null,
            screenStream: null, screenSharing: false,
            audioMuted: false, videoMuted: false
        });

        hideModal();
    }

    // ── In-call controls ──────────────────────────────────────────────────────
    function toggleAudio() {
        if (!gc.localStream) return;
        gc.audioMuted = !gc.audioMuted;
        gc.localStream.getAudioTracks().forEach(t => { t.enabled = !gc.audioMuted; });
        if (els.muteAudio) {
            els.muteAudio.innerHTML = gc.audioMuted
                ? '<i class="fas fa-microphone-slash"></i>'
                : '<i class="fas fa-microphone"></i>';
            els.muteAudio.style.background = gc.audioMuted ? 'var(--danger)' : '';
        }
    }

    function toggleVideo() {
        if (!gc.localStream) return;
        gc.videoMuted = !gc.videoMuted;
        gc.localStream.getVideoTracks().forEach(t => { t.enabled = !gc.videoMuted; });
        if (els.muteVideo) {
            els.muteVideo.innerHTML = gc.videoMuted
                ? '<i class="fas fa-video-slash"></i>'
                : '<i class="fas fa-video"></i>';
            els.muteVideo.style.background = gc.videoMuted ? 'var(--danger)' : '';
        }
    }

    async function toggleScreen() {
        if (!gc.active || gc.callType !== 'video') return;
        if (gc.screenSharing) {
            gc.screenStream.getTracks().forEach(t => t.stop());
            gc.screenStream  = null;
            gc.screenSharing = false;
            const cam = gc.localStream ? gc.localStream.getVideoTracks()[0] : null;
            if (cam) {
                Object.values(gc.peers).forEach(pc => {
                    const s = pc.getSenders().find(x => x.track && x.track.kind === 'video');
                    if (s) s.replaceTrack(cam);
                });
            }
            if (els.shareScreen) { els.shareScreen.classList.remove('active'); els.shareScreen.title = 'Share Screen'; }
        } else {
            try {
                gc.screenStream = await navigator.mediaDevices.getDisplayMedia({ video: true });
                const st = gc.screenStream.getVideoTracks()[0];
                gc.screenSharing = true;
                Object.values(gc.peers).forEach(pc => {
                    const s = pc.getSenders().find(x => x.track && x.track.kind === 'video');
                    if (s) s.replaceTrack(st);
                });
                if (els.shareScreen) { els.shareScreen.classList.add('active'); els.shareScreen.title = 'Stop Sharing'; }
                st.onended = () => { if (gc.screenSharing) toggleScreen(); };
            } catch (e) { /* user cancelled */ }
        }
    }

    // ── Socket events ─────────────────────────────────────────────────────────
    function bindSocket() {
        const s = sock();
        if (!s) { setTimeout(bindSocket, 100); return; }

        // Server confirmed we joined — initiate offers to existing participants
        s.on('group_call_joined', data => {
            gc.callRoom = data.call_room;
            if (els.status) els.status.textContent = 'Connecting…';
            data.existing_participants.forEach(user => createPeer(user, true));
            updateCount();
        });

        // New participant joined — they will send us an offer
        s.on('group_call_user_joined', data => {
            if (!gc.active) return;
            if (!gc.peers[data.username]) createPeer(data.username, false);
            updateCount();
        });

        // Participant left
        s.on('group_call_user_left', data => {
            removeTile(data.username);
            if (gc.peers[data.username]) { gc.peers[data.username].close(); delete gc.peers[data.username]; }
            updateCount();
        });

        // Incoming group call notification
        s.on('incoming_group_call', data => {
            if (gc.active) return; // already in a call
            gc.pendingIncoming = data;
            if (els.groupName)    els.groupName.textContent   = data.group_name;
            if (els.callerName)   els.callerName.textContent  = `${data.started_by} started a call${data.participant_count > 1 ? ` · ${data.participant_count} in call` : ''}`;
            if (els.callTypeText) els.callTypeText.textContent = data.type === 'video' ? 'Video Call' : 'Audio Call';
            if (els.incomingModal) els.incomingModal.style.display = 'flex';
        });

        // WebRTC offer from a peer
        s.on('group_webrtc_offer', async data => {
            if (data.call_room !== gc.callRoom) return;
            let pc = gc.peers[data.sender] || createPeer(data.sender, false);
            try {
                await pc.setRemoteDescription(new RTCSessionDescription(data.offer));
                const ans = await pc.createAnswer();
                await pc.setLocalDescription(ans);
                s.emit('group_webrtc_answer', { call_room: gc.callRoom, target: data.sender, answer: pc.localDescription });
            } catch (e) { console.error('Group offer handling error:', e); }
        });

        // WebRTC answer from a peer
        s.on('group_webrtc_answer', async data => {
            if (data.call_room !== gc.callRoom) return;
            const pc = gc.peers[data.sender];
            if (pc && pc.signalingState !== 'stable') {
                try { await pc.setRemoteDescription(new RTCSessionDescription(data.answer)); }
                catch (e) { console.error('Group answer handling error:', e); }
            }
        });

        // ICE candidate from a peer
        s.on('group_webrtc_ice', async data => {
            if (data.call_room !== gc.callRoom) return;
            const pc = gc.peers[data.sender];
            if (pc && data.candidate) {
                try { await pc.addIceCandidate(new RTCIceCandidate(data.candidate)); }
                catch (e) { /* benign */ }
            }
        });
    }

    // ── Button bindings ───────────────────────────────────────────────────────
    function bindButtons() {
        if (els.audioBtnHeader) els.audioBtnHeader.addEventListener('click', () => {
            const r = window.currentGroupRoom;
            if (r) startCall(r, 'audio'); else window.showOverlay?.('Select a group first.');
        });
        if (els.videoBtnHeader) els.videoBtnHeader.addEventListener('click', () => {
            const r = window.currentGroupRoom;
            if (r) startCall(r, 'video'); else window.showOverlay?.('Select a group first.');
        });

        if (els.muteAudio)  els.muteAudio.addEventListener('click', toggleAudio);
        if (els.muteVideo)  els.muteVideo.addEventListener('click', toggleVideo);
        if (els.shareScreen)els.shareScreen.addEventListener('click', toggleScreen);
        if (els.endCall)    els.endCall.addEventListener('click', leaveCall);

        if (els.minimize) {
            els.minimize.addEventListener('click', () => {
                if (els.modal) els.modal.style.display = 'none';
            });
        }

        if (els.answer) {
            els.answer.addEventListener('click', async () => {
                const inc = gc.pendingIncoming;
                if (!inc) return;
                if (els.incomingModal) els.incomingModal.style.display = 'none';

                gc.callRoom  = inc.call_room;
                gc.groupRoom = inc.room;
                gc.callType  = inc.type;

                try {
                    gc.localStream = await getMedia(inc.type);
                } catch (err) {
                    window.showOverlay?.('Could not access camera/microphone: ' + err.message);
                    return;
                }

                if (els.localVideo) els.localVideo.srcObject = gc.localStream;
                showModal(inc.type);
                if (els.status) els.status.textContent = 'Joining…';

                sock().emit('group_call_start', { room: inc.room, type: inc.type });
                gc.pendingIncoming = null;
            });
        }

        if (els.reject) {
            els.reject.addEventListener('click', () => {
                if (gc.pendingIncoming) {
                    sock().emit('group_call_reject', { call_room: gc.pendingIncoming.call_room });
                }
                if (els.incomingModal) els.incomingModal.style.display = 'none';
                gc.pendingIncoming = null;
            });
        }
    }

    // ── Init ──────────────────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', () => {
        bindButtons();
        bindSocket();
    });

    window.groupCall = gc;
    window.startGroupCall = startCall;
    window.leaveGroupCall = leaveCall;

}());