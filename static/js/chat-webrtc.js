/**
 * chat-webrtc.js  —  1-to-1 audio/video calls for Kryonix
 *
 * Design:
 *  - Caller clicks the phone/video button → emits call_user to server
 *  - Server relays incoming_call to callee
 *  - Callee sees modal → answer or reject
 *  - On answer: both sides join a shared socket room; caller creates
 *    RTCPeerConnection and sends offer; callee answers; ICE exchange follows
 *  - Either party can end the call at any time
 *  - Screen-share, mute-audio, mute-video supported in-call
 *  - Device-selector modal (mic / camera) accessible from in-call settings btn
 */

(function () {
    'use strict';

    // ── ICE servers ───────────────────────────────────────────────────────────
    const ICE_CONFIG = {
        iceServers: [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' },
            { urls: 'stun:stun2.l.google.com:19302' }
        ]
    };

    // ── Call state ────────────────────────────────────────────────────────────
    const call = {
        active:        false,
        isCaller:      false,
        callType:      null,    // 'video' | 'audio'
        room:          null,    // shared socket room for signalling
        peer:          null,    // RTCPeerConnection
        localStream:   null,
        remoteStream:  null,
        screenStream:  null,
        screenSharing: false,
        audioMuted:    false,
        videoMuted:    false,
        // For callee: remember who called us so we can emit answer_call
        callerName:    null,
        incomingType:  null,
        // Ringing timeout — auto-dismiss incoming if no answer in 45 s
        ringTimer:     null,
    };

    // ── DOM ───────────────────────────────────────────────────────────────────
    const callModal          = document.getElementById('call-modal');
    const incomingCallModal  = document.getElementById('incoming-call-modal');
    const deviceSettingsModal= document.getElementById('device-settings-modal');

    const remoteVideo        = document.getElementById('remote-video');
    const localVideo         = document.getElementById('local-video');

    const callTitle          = document.getElementById('call-title');
    const callStatus         = document.getElementById('call-status');
    const callerNameEl       = document.getElementById('caller-name');
    const callTypeText       = document.getElementById('call-type-text');

    const audioCallBtn       = document.getElementById('audio-call-btn');
    const videoCallBtn       = document.getElementById('video-call-btn');
    const muteAudioBtn       = document.getElementById('mute-audio-btn');
    const muteVideoBtn       = document.getElementById('mute-video-btn');
    const shareScreenBtn     = document.getElementById('share-screen-btn');
    const endCallBtn         = document.getElementById('end-call-btn');
    const minimizeCallBtn    = document.getElementById('minimize-call-btn');
    const settingsCallBtn    = document.getElementById('settings-call-btn');
    const answerCallBtn      = document.getElementById('answer-call-btn');
    const rejectCallBtn      = document.getElementById('reject-call-btn');

    const micSelect          = document.getElementById('microphone-select');
    const camSelect          = document.getElementById('camera-select');
    const saveSettingsBtn    = document.getElementById('save-settings-btn');
    const cancelSettingsBtn  = document.getElementById('cancel-settings-btn');

    // ── Helpers ───────────────────────────────────────────────────────────────
    function getSocket()   { return window.socket; }
    function getUsername() { return window.username || document.querySelector('.username').textContent.trim(); }

    function currentDirectFriend() {
        // Returns the friend username from the active 1-to-1 room, or null
        const room = window.currentRoom;
        if (!room || room.startsWith('group_')) return null;
        return room.split('-').find(u => u !== getUsername()) || null;
    }

    function setCallStatus(text) {
        if (callStatus) callStatus.textContent = text;
    }

    // ── Show / hide modals ────────────────────────────────────────────────────
    function openCallModal(type) {
        if (!callModal) return;
        callModal.style.display = 'flex';
        if (callTitle) callTitle.textContent = type === 'video' ? 'Video Call' : 'Audio Call';
        if (type === 'audio') {
            // Hide local video element for audio-only calls
            if (localVideo)  localVideo.style.display  = 'none';
            if (remoteVideo) remoteVideo.style.display = 'none';
        } else {
            if (localVideo)  localVideo.style.display  = '';
            if (remoteVideo) remoteVideo.style.display = '';
        }
        // Show/hide the mute-video button depending on call type
        if (muteVideoBtn) muteVideoBtn.style.display = type === 'video' ? '' : 'none';
        if (shareScreenBtn) shareScreenBtn.style.display = type === 'video' ? '' : 'none';
    }

    function closeCallModal() {
        if (callModal) callModal.style.display = 'none';
    }

    function openIncomingModal(callerName, type) {
        if (!incomingCallModal) return;
        if (callerNameEl) callerNameEl.textContent = `${callerName} is calling you…`;
        if (callTypeText) callTypeText.textContent = type === 'video' ? 'Video Call' : 'Audio Call';
        incomingCallModal.style.display = 'flex';
    }

    function closeIncomingModal() {
        if (incomingCallModal) incomingCallModal.style.display = 'none';
        clearTimeout(call.ringTimer);
    }

    // ── Media helpers ─────────────────────────────────────────────────────────
    async function getLocalMedia(type) {
        const constraints = type === 'video'
            ? { audio: { echoCancellation: true, noiseSuppression: true }, video: { width: { ideal: 1280 }, height: { ideal: 720 } } }
            : { audio: { echoCancellation: true, noiseSuppression: true }, video: false };
        return navigator.mediaDevices.getUserMedia(constraints);
    }

    function attachLocalStream(stream) {
        call.localStream = stream;
        if (localVideo) {
            localVideo.srcObject = stream;
            localVideo.muted = true;
        }
    }

    function attachRemoteStream(stream) {
        call.remoteStream = stream;
        if (remoteVideo) remoteVideo.srcObject = stream;
    }

    // ── Peer connection ───────────────────────────────────────────────────────
    function buildPeerConnection() {
        const pc = new RTCPeerConnection(ICE_CONFIG);

        // Add local tracks
        if (call.localStream) {
            call.localStream.getTracks().forEach(track => pc.addTrack(track, call.localStream));
        }

        // Receive remote tracks
        const remoteStream = new MediaStream();
        pc.ontrack = evt => {
            evt.streams[0].getTracks().forEach(t => remoteStream.addTrack(t));
            attachRemoteStream(remoteStream);
        };

        // ICE candidates → send to peer via server
        pc.onicecandidate = evt => {
            if (evt.candidate) {
                getSocket().emit('webrtc_ice_candidate', {
                    room: call.room,
                    candidate: evt.candidate
                });
            }
        };

        pc.onconnectionstatechange = () => {
            switch (pc.connectionState) {
                case 'connected':
                    setCallStatus('Connected');
                    break;
                case 'connecting':
                    setCallStatus('Connecting…');
                    break;
                case 'disconnected':
                case 'failed':
                    setCallStatus('Connection lost');
                    // Attempt ICE restart once
                    if (pc.connectionState === 'failed') {
                        pc.restartIce();
                    }
                    break;
                case 'closed':
                    endCallCleanup();
                    break;
            }
        };

        return pc;
    }

    // ── Initiate call (caller side) ───────────────────────────────────────────
    async function startCall(type) {
        if (call.active) return;

        const friend = currentDirectFriend();
        if (!friend) return;

        try {
            await attachLocalStream(await getLocalMedia(type));
        } catch (err) {
            showUserError('Could not access your ' + (type === 'video' ? 'camera/microphone' : 'microphone') + ': ' + err.message);
            return;
        }

        call.isCaller   = true;
        call.callType   = type;
        call.callerName = getUsername();
        // Room is a deterministic shared name both sides can derive
        call.room = ['call', getUsername(), friend].sort().join('_');

        openCallModal(type);
        setCallStatus('Calling…');

        getSocket().emit('call_user', {
            receiver: friend,
            type:     type,
            room:     call.room
        });
    }

    // ── Caller: remote answered ───────────────────────────────────────────────
    async function onCallAnswered(data) {
        setCallStatus('Connected — setting up…');
        call.peer = buildPeerConnection();

        try {
            const offer = await call.peer.createOffer();
            await call.peer.setLocalDescription(offer);
            getSocket().emit('webrtc_offer', { room: call.room, offer: call.peer.localDescription });
        } catch (err) {
            showUserError('Failed to create call offer.');
            endCallCleanup();
        }
    }

    // ── Callee: incoming call notification ────────────────────────────────────
    function onIncomingCall(data) {
        if (call.active) {
            // Already in a call — auto-reject
            getSocket().emit('reject_call', { caller: data.caller, room: data.room });
            return;
        }
        call.callerName   = data.caller;
        call.room         = data.room;
        call.incomingType = data.type;

        openIncomingModal(data.caller, data.type);

        // Auto-dismiss ringing after 45 s
        call.ringTimer = setTimeout(() => {
            closeIncomingModal();
            getSocket().emit('reject_call', { caller: data.caller, room: data.room });
        }, 45000);
    }

    // ── Callee: answer ────────────────────────────────────────────────────────
    async function answerCall() {
        closeIncomingModal();

        try {
            await attachLocalStream(await getLocalMedia(call.incomingType));
        } catch (err) {
            showUserError('Could not access your ' + (call.incomingType === 'video' ? 'camera/microphone' : 'microphone') + ': ' + err.message);
            return;
        }

        call.active   = true;
        call.isCaller = false;
        call.callType = call.incomingType;
        call.peer     = buildPeerConnection();

        openCallModal(call.callType);
        setCallStatus('Connecting…');

        getSocket().emit('answer_call', {
            caller: call.callerName,
            room:   call.room,
            type:   call.callType
        });
    }

    // ── Callee: reject ────────────────────────────────────────────────────────
    function rejectCall() {
        closeIncomingModal();
        getSocket().emit('reject_call', { caller: call.callerName, room: call.room });
        call.callerName   = null;
        call.room         = null;
        call.incomingType = null;
    }

    // ── Receive WebRTC offer (callee) ─────────────────────────────────────────
    async function onWebRTCOffer(data) {
        if (!call.peer) return;
        try {
            await call.peer.setRemoteDescription(new RTCSessionDescription(data.offer));
            const answer = await call.peer.createAnswer();
            await call.peer.setLocalDescription(answer);
            getSocket().emit('webrtc_answer', { room: call.room, answer: call.peer.localDescription });
            setCallStatus('Connected');
        } catch (err) {
            console.error('Error handling offer:', err);
        }
    }

    // ── Receive WebRTC answer (caller) ────────────────────────────────────────
    async function onWebRTCAnswer(data) {
        if (!call.peer || call.peer.signalingState === 'stable') return;
        try {
            await call.peer.setRemoteDescription(new RTCSessionDescription(data.answer));
        } catch (err) {
            console.error('Error handling answer:', err);
        }
    }

    // ── Receive ICE candidate ─────────────────────────────────────────────────
    async function onIceCandidate(data) {
        if (!call.peer || !data.candidate) return;
        try {
            await call.peer.addIceCandidate(new RTCIceCandidate(data.candidate));
        } catch (err) {
            // Benign: can happen when late ICE candidates arrive after close
        }
    }

    // ── End call ──────────────────────────────────────────────────────────────
    function hangUp() {
        if (!call.room) return;
        getSocket().emit('end_call', { room: call.room });
        endCallCleanup();
    }

    function endCallCleanup() {
        // Stop all media tracks
        [call.localStream, call.screenStream].forEach(stream => {
            if (stream) stream.getTracks().forEach(t => t.stop());
        });
        if (call.peer) { call.peer.close(); }

        // Reset local/remote video elements
        if (localVideo)  { localVideo.srcObject  = null; localVideo.style.display  = ''; }
        if (remoteVideo) { remoteVideo.srcObject = null; remoteVideo.style.display = ''; }

        // Reset button icons
        if (muteAudioBtn)  muteAudioBtn.innerHTML  = '<i class="fas fa-microphone"></i>';
        if (muteVideoBtn)  muteVideoBtn.innerHTML  = '<i class="fas fa-video"></i>';
        if (shareScreenBtn) shareScreenBtn.classList.remove('active');
        if (muteAudioBtn)  muteAudioBtn.classList.remove('active');
        if (muteVideoBtn)  muteVideoBtn.classList.remove('active');

        // Reset state
        Object.assign(call, {
            active: false, isCaller: false, callType: null, room: null,
            peer: null, localStream: null, remoteStream: null,
            screenStream: null, screenSharing: false,
            audioMuted: false, videoMuted: false,
            callerName: null, incomingType: null
        });

        closeCallModal();
    }

    // ── Mute / camera / screen share ──────────────────────────────────────────
    function toggleAudio() {
        if (!call.localStream) return;
        call.audioMuted = !call.audioMuted;
        call.localStream.getAudioTracks().forEach(t => { t.enabled = !call.audioMuted; });
        if (muteAudioBtn) {
            muteAudioBtn.innerHTML = call.audioMuted
                ? '<i class="fas fa-microphone-slash"></i>'
                : '<i class="fas fa-microphone"></i>';
            muteAudioBtn.classList.toggle('active', call.audioMuted);
            muteAudioBtn.style.background = call.audioMuted ? 'var(--danger)' : '';
        }
    }

    function toggleVideo() {
        if (!call.localStream) return;
        call.videoMuted = !call.videoMuted;
        call.localStream.getVideoTracks().forEach(t => { t.enabled = !call.videoMuted; });
        if (muteVideoBtn) {
            muteVideoBtn.innerHTML = call.videoMuted
                ? '<i class="fas fa-video-slash"></i>'
                : '<i class="fas fa-video"></i>';
            muteVideoBtn.classList.toggle('active', call.videoMuted);
            muteVideoBtn.style.background = call.videoMuted ? 'var(--danger)' : '';
        }
    }

    async function toggleScreenShare() {
        if (!call.active || call.callType !== 'video') return;

        if (call.screenSharing) {
            // Revert to camera
            call.screenStream.getTracks().forEach(t => t.stop());
            call.screenStream  = null;
            call.screenSharing = false;

            const cameraTrack = call.localStream ? call.localStream.getVideoTracks()[0] : null;
            if (cameraTrack && call.peer) {
                const sender = call.peer.getSenders().find(s => s.track && s.track.kind === 'video');
                if (sender) sender.replaceTrack(cameraTrack);
            }
            if (shareScreenBtn) {
                shareScreenBtn.classList.remove('active');
                shareScreenBtn.title = 'Share Screen';
            }
        } else {
            try {
                call.screenStream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
                const screenTrack = call.screenStream.getVideoTracks()[0];
                call.screenSharing = true;

                if (call.peer) {
                    const sender = call.peer.getSenders().find(s => s.track && s.track.kind === 'video');
                    if (sender) sender.replaceTrack(screenTrack);
                }
                if (shareScreenBtn) {
                    shareScreenBtn.classList.add('active');
                    shareScreenBtn.title = 'Stop Sharing';
                }

                // Auto-revert when user stops via browser UI
                screenTrack.onended = () => { if (call.screenSharing) toggleScreenShare(); };
            } catch (err) {
                if (err.name !== 'NotAllowedError') {
                    showUserError('Could not share screen: ' + err.message);
                }
            }
        }
    }

    // ── Minimise ──────────────────────────────────────────────────────────────
    function toggleMinimize() {
        if (!callModal) return;
        callModal.classList.toggle('minimized');
        if (minimizeCallBtn) {
            minimizeCallBtn.innerHTML = callModal.classList.contains('minimized')
                ? '<i class="fas fa-expand"></i>'
                : '<i class="fas fa-minus"></i>';
        }
    }

    // ── Device settings ───────────────────────────────────────────────────────
    async function openDeviceSettings() {
        if (!deviceSettingsModal) return;

        try {
            const devices = await navigator.mediaDevices.enumerateDevices();
            const mics    = devices.filter(d => d.kind === 'audioinput');
            const cams    = devices.filter(d => d.kind === 'videoinput');

            if (micSelect) {
                micSelect.innerHTML = mics.map(d =>
                    `<option value="${d.deviceId}">${d.label || 'Microphone ' + (mics.indexOf(d) + 1)}</option>`
                ).join('');
            }
            if (camSelect) {
                camSelect.innerHTML = cams.map(d =>
                    `<option value="${d.deviceId}">${d.label || 'Camera ' + (cams.indexOf(d) + 1)}</option>`
                ).join('');
            }
        } catch (err) {
            console.warn('Could not enumerate devices:', err);
        }

        deviceSettingsModal.style.display = 'block';
    }

    async function applyDeviceSettings() {
        if (!deviceSettingsModal) return;
        deviceSettingsModal.style.display = 'none';

        if (!call.active || !call.localStream) return;

        const micId = micSelect ? micSelect.value : null;
        const camId = camSelect ? camSelect.value : null;

        try {
            const newStream = await navigator.mediaDevices.getUserMedia({
                audio: micId ? { deviceId: { exact: micId } } : true,
                video: call.callType === 'video'
                    ? (camId ? { deviceId: { exact: camId } } : true)
                    : false
            });

            // Stop old tracks
            call.localStream.getTracks().forEach(t => t.stop());
            attachLocalStream(newStream);

            // Replace tracks in peer connection
            if (call.peer) {
                newStream.getTracks().forEach(newTrack => {
                    const sender = call.peer.getSenders().find(s => s.track && s.track.kind === newTrack.kind);
                    if (sender) sender.replaceTrack(newTrack);
                });
            }
        } catch (err) {
            showUserError('Could not switch device: ' + err.message);
        }
    }

    // ── Silent user-visible error (no ugly alerts) ────────────────────────────
    function showUserError(msg) {
        // Use the global showOverlay if available, otherwise silent console
        if (typeof window.showOverlay === 'function') {
            window.showOverlay(msg);
        } else {
            console.warn('[WebRTC]', msg);
        }
    }

    // ── Socket event bindings ─────────────────────────────────────────────────
    function bindSocketEvents() {
        const socket = getSocket();
        if (!socket) {
            setTimeout(bindSocketEvents, 100);
            return;
        }

        socket.on('call_answered',      onCallAnswered);
        socket.on('incoming_call',      onIncomingCall);
        socket.on('call_rejected',      (data) => {
            endCallCleanup();
            // No overlay — just silently reset. The user knows they were rejected.
        });
        socket.on('call_ended',         () => { endCallCleanup(); });
        socket.on('webrtc_offer',       onWebRTCOffer);
        socket.on('webrtc_answer',      onWebRTCAnswer);
        socket.on('webrtc_ice_candidate', onIceCandidate);
    }

    // ── Button bindings ───────────────────────────────────────────────────────
    function bindButtons() {
        if (audioCallBtn)  audioCallBtn.addEventListener('click',  () => startCall('audio'));
        if (videoCallBtn)  videoCallBtn.addEventListener('click',  () => startCall('video'));
        if (answerCallBtn) answerCallBtn.addEventListener('click', answerCall);
        if (rejectCallBtn) rejectCallBtn.addEventListener('click', rejectCall);
        if (endCallBtn)    endCallBtn.addEventListener('click',    hangUp);
        if (muteAudioBtn)  muteAudioBtn.addEventListener('click',  toggleAudio);
        if (muteVideoBtn)  muteVideoBtn.addEventListener('click',  toggleVideo);
        if (shareScreenBtn)shareScreenBtn.addEventListener('click',toggleScreenShare);
        if (minimizeCallBtn)minimizeCallBtn.addEventListener('click', toggleMinimize);
        if (settingsCallBtn)settingsCallBtn.addEventListener('click', openDeviceSettings);
        if (saveSettingsBtn)saveSettingsBtn.addEventListener('click', applyDeviceSettings);
        if (cancelSettingsBtn) cancelSettingsBtn.addEventListener('click', () => {
            if (deviceSettingsModal) deviceSettingsModal.style.display = 'none';
        });

        // Click outside device-settings modal to close
        if (deviceSettingsModal) {
            deviceSettingsModal.addEventListener('click', e => {
                if (e.target === deviceSettingsModal) deviceSettingsModal.style.display = 'none';
            });
        }
    }

    // ── Init ──────────────────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', () => {
        bindButtons();
        bindSocketEvents();
    });

    // Expose minimal API for debugging
    window._webrtcCall = call;

}());