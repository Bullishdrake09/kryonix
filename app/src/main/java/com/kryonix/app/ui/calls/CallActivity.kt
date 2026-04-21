package com.kryonix.app.ui.calls

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.kryonix.app.KryonixApplication
import com.kryonix.app.api.SocketManager
import com.kryonix.app.databinding.ActivityCallBinding
import kotlinx.coroutines.launch
import org.json.JSONObject
import org.webrtc.*

class CallActivity : AppCompatActivity() {

    private lateinit var binding: ActivityCallBinding

    private var mode      = "outgoing"   // "outgoing" | "incoming"
    private var caller    = ""
    private var callee    = ""
    private var callRoom  = ""
    private var callType  = "video"
    private var myUsername = ""

    // WebRTC
    private var peerConnectionFactory: PeerConnectionFactory? = null
    private var peerConnection: PeerConnection? = null
    private var localVideoTrack: VideoTrack? = null
    private var localAudioTrack: AudioTrack? = null
    private var localStream: MediaStream? = null
    private var eglBase: EglBase? = null
    private var isMuted   = false
    private var isCameraOff = false

    companion object {
        private const val PERMISSIONS_RC = 101
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON or
                        WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                        WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON)

        binding = ActivityCallBinding.inflate(layoutInflater)
        setContentView(binding.root)

        mode     = intent.getStringExtra("mode")      ?: "outgoing"
        caller   = intent.getStringExtra("caller")    ?: ""
        callee   = intent.getStringExtra("callee")    ?: ""
        callRoom = intent.getStringExtra("room")      ?: ""
        callType = intent.getStringExtra("call_type") ?: "video"

        lifecycleScope.launch {
            myUsername = (application as KryonixApplication).sessionManager.getUsername() ?: ""
            setupUI()
            setupSocketListeners()
        }

        checkPermissionsAndInit()
    }

    private fun setupUI() {
        val remoteName = if (mode == "incoming") caller else callee
        binding.tvRemoteUser.text = remoteName

        if (callType == "audio") {
            binding.localSurfaceView.visibility  = View.GONE
            binding.remoteSurfaceView.visibility = View.GONE
            binding.ivCallTypeIcon.visibility    = View.VISIBLE
        }

        if (mode == "incoming") {
            binding.llIncomingControls.visibility = View.VISIBLE
            binding.llCallControls.visibility     = View.GONE
            binding.tvCallStatus.text             = "Incoming ${callType} call from $caller"

            binding.btnAccept.setOnClickListener {
                binding.llIncomingControls.visibility = View.GONE
                binding.llCallControls.visibility     = View.VISIBLE
                SocketManager.answerCall(caller, callRoom, callType)
                startWebRTC(isInitiator = false)
            }
            binding.btnDecline.setOnClickListener {
                SocketManager.rejectCall(caller, callRoom)
                finish()
            }
        } else {
            binding.llIncomingControls.visibility = View.GONE
            binding.llCallControls.visibility     = View.VISIBLE
            binding.tvCallStatus.text             = "Calling $callee…"
        }

        binding.btnEndCall.setOnClickListener    { endCall() }
        binding.btnToggleMute.setOnClickListener { toggleMute() }
        binding.btnToggleCamera.setOnClickListener { toggleCamera() }
        binding.btnSwitchCamera.setOnClickListener { switchCamera() }
    }

    private fun checkPermissionsAndInit() {
        val perms = mutableListOf(Manifest.permission.RECORD_AUDIO)
        if (callType == "video") perms.add(Manifest.permission.CAMERA)
        val missing = perms.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) initWebRTC()
        else ActivityCompat.requestPermissions(this, missing.toTypedArray(), PERMISSIONS_RC)
    }

    override fun onRequestPermissionsResult(rc: Int, perms: Array<out String>, grants: IntArray) {
        super.onRequestPermissionsResult(rc, perms, grants)
        if (rc == PERMISSIONS_RC && grants.all { it == PackageManager.PERMISSION_GRANTED })
            initWebRTC()
        else { binding.tvCallStatus.text = "Permissions denied"; }
    }

    private fun initWebRTC() {
        eglBase = EglBase.create()

        // Init PeerConnectionFactory
        val initOptions = PeerConnectionFactory.InitializationOptions.builder(applicationContext)
            .setEnableInternalTracer(false)
            .createInitializationOptions()
        PeerConnectionFactory.initialize(initOptions)

        val encoderFactory = DefaultVideoEncoderFactory(eglBase!!.eglBaseContext, true, true)
        val decoderFactory = DefaultVideoDecoderFactory(eglBase!!.eglBaseContext)

        peerConnectionFactory = PeerConnectionFactory.builder()
            .setVideoEncoderFactory(encoderFactory)
            .setVideoDecoderFactory(decoderFactory)
            .createPeerConnectionFactory()

        // Local video/audio
        val audioSource = peerConnectionFactory!!.createAudioSource(MediaConstraints())
        localAudioTrack = peerConnectionFactory!!.createAudioTrack("audio0", audioSource)

        if (callType == "video") {
            binding.localSurfaceView.init(eglBase!!.eglBaseContext, null)
            binding.localSurfaceView.setMirror(true)
            binding.remoteSurfaceView.init(eglBase!!.eglBaseContext, null)

            val videoSource   = peerConnectionFactory!!.createVideoSource(false)
            val surfaceHelper = SurfaceTextureHelper.create("CaptureThread", eglBase!!.eglBaseContext)
            val videoCapturer = createCameraCapturer()
            videoCapturer?.initialize(surfaceHelper, applicationContext, videoSource.capturerObserver)
            videoCapturer?.startCapture(1280, 720, 30)

            localVideoTrack = peerConnectionFactory!!.createVideoTrack("video0", videoSource)
            localVideoTrack!!.addSink(binding.localSurfaceView)
        }

        localStream = peerConnectionFactory!!.createLocalMediaStream("local")
        localAudioTrack?.let { localStream!!.addTrack(it) }
        localVideoTrack?.let { localStream!!.addTrack(it) }

        if (mode == "outgoing") startWebRTC(isInitiator = true)
    }

    private fun createCameraCapturer(): CameraVideoCapturer? {
        val enumerator = Camera2Enumerator(this)
        // Try front camera first
        enumerator.deviceNames.forEach { name ->
            if (enumerator.isFrontFacing(name))
                return enumerator.createCapturer(name, null)
        }
        enumerator.deviceNames.forEach { name ->
            if (!enumerator.isFrontFacing(name))
                return enumerator.createCapturer(name, null)
        }
        return null
    }

    private fun startWebRTC(isInitiator: Boolean) {
        val iceServers = listOf(
            PeerConnection.IceServer.builder("stun:stun.l.google.com:19302").createIceServer(),
            PeerConnection.IceServer.builder("stun:stun1.l.google.com:19302").createIceServer()
        )
        val config = PeerConnection.RTCConfiguration(iceServers).apply {
            sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
        }

        peerConnection = peerConnectionFactory!!.createPeerConnection(config, object : PeerConnection.Observer {
            override fun onIceCandidate(candidate: IceCandidate) {
                val json = JSONObject().apply {
                    put("sdpMid", candidate.sdpMid)
                    put("sdpMLineIndex", candidate.sdpMLineIndex)
                    put("candidate", candidate.sdp)
                }
                SocketManager.sendIceCandidate(json, callRoom)
            }
            override fun onAddStream(stream: MediaStream) {
                stream.videoTracks.firstOrNull()?.let { track ->
                    runOnUiThread {
                        if (callType == "video")
                            track.addSink(binding.remoteSurfaceView)
                    }
                }
            }
            override fun onIceConnectionChange(state: PeerConnection.IceConnectionState) {
                runOnUiThread {
                    when (state) {
                        PeerConnection.IceConnectionState.CONNECTED     -> {
                            binding.tvCallStatus.text = "Connected"
                        }
                        PeerConnection.IceConnectionState.DISCONNECTED,
                        PeerConnection.IceConnectionState.FAILED        -> endCall()
                        else -> {}
                    }
                }
            }
            override fun onSignalingChange(p0: PeerConnection.SignalingState?)   {}
            override fun onIceConnectionReceivingChange(p0: Boolean)             {}
            override fun onIceGatheringChange(p0: PeerConnection.IceGatheringState?) {}
            override fun onIceCandidatesRemoved(p0: Array<out IceCandidate>?)    {}
            override fun onRemoveStream(p0: MediaStream?)                        {}
            override fun onDataChannel(p0: DataChannel?)                         {}
            override fun onRenegotiationNeeded()                                 {}
            override fun onAddTrack(p0: RtpReceiver?, p1: Array<out MediaStream>?) {}
        })

        localStream?.let { peerConnection!!.addStream(it) }

        if (isInitiator) createOffer()
    }

    private fun createOffer() {
        val constraints = MediaConstraints().apply {
            mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "true"))
            if (callType == "video")
                mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveVideo", "true"))
        }
        peerConnection!!.createOffer(object : SdpObserver {
            override fun onCreateSuccess(sdp: SessionDescription) {
                peerConnection!!.setLocalDescription(object : SdpObserver {
                    override fun onSetSuccess() {
                        val json = JSONObject().apply {
                            put("type", sdp.type.canonicalForm())
                            put("sdp", sdp.description)
                        }
                        SocketManager.sendWebRtcOffer(json, callRoom)
                    }
                    override fun onSetFailure(p0: String?) {}
                    override fun onCreateSuccess(p0: SessionDescription?) {}
                    override fun onCreateFailure(p0: String?) {}
                }, sdp)
            }
            override fun onSetSuccess()              {}
            override fun onCreateFailure(p0: String?) {}
            override fun onSetFailure(p0: String?)   {}
        }, constraints)
    }

    private fun setupSocketListeners() {
        SocketManager.on("webrtc_offer") { args ->
            val data  = args[0] as? JSONObject ?: return@on
            val offer = data.optJSONObject("offer") ?: return@on
            val sdp   = SessionDescription(SessionDescription.Type.OFFER, offer.optString("sdp"))
            peerConnection?.setRemoteDescription(object : SdpObserver {
                override fun onSetSuccess() { createAnswer() }
                override fun onSetFailure(p0: String?) {}
                override fun onCreateSuccess(p0: SessionDescription?) {}
                override fun onCreateFailure(p0: String?) {}
            }, sdp)
        }

        SocketManager.on("webrtc_answer") { args ->
            val data   = args[0] as? JSONObject ?: return@on
            val answer = data.optJSONObject("answer") ?: return@on
            val sdp    = SessionDescription(SessionDescription.Type.ANSWER, answer.optString("sdp"))
            peerConnection?.setRemoteDescription(object : SdpObserver {
                override fun onSetSuccess() {}
                override fun onSetFailure(p0: String?) {}
                override fun onCreateSuccess(p0: SessionDescription?) {}
                override fun onCreateFailure(p0: String?) {}
            }, sdp)
        }

        SocketManager.on("webrtc_ice_candidate") { args ->
            val data      = args[0] as? JSONObject ?: return@on
            val candidateJson = data.optJSONObject("candidate") ?: return@on
            val candidate = IceCandidate(
                candidateJson.optString("sdpMid"),
                candidateJson.optInt("sdpMLineIndex"),
                candidateJson.optString("candidate")
            )
            peerConnection?.addIceCandidate(candidate)
        }

        SocketManager.on("call_ended") { _ ->
            runOnUiThread { endCall() }
        }

        SocketManager.on("call_rejected") { _ ->
            runOnUiThread {
                binding.tvCallStatus.text = "Call declined"
                android.os.Handler(mainLooper).postDelayed({ finish() }, 1500)
            }
        }
    }

    private fun createAnswer() {
        val constraints = MediaConstraints()
        peerConnection!!.createAnswer(object : SdpObserver {
            override fun onCreateSuccess(sdp: SessionDescription) {
                peerConnection!!.setLocalDescription(object : SdpObserver {
                    override fun onSetSuccess() {
                        val json = JSONObject().apply {
                            put("type", sdp.type.canonicalForm())
                            put("sdp", sdp.description)
                        }
                        SocketManager.sendWebRtcAnswer(json, callRoom)
                    }
                    override fun onSetFailure(p0: String?) {}
                    override fun onCreateSuccess(p0: SessionDescription?) {}
                    override fun onCreateFailure(p0: String?) {}
                }, sdp)
            }
            override fun onSetSuccess() {}
            override fun onCreateFailure(p0: String?) {}
            override fun onSetFailure(p0: String?) {}
        }, constraints)
    }

    private fun toggleMute() {
        isMuted = !isMuted
        localAudioTrack?.setEnabled(!isMuted)
        binding.btnToggleMute.setImageResource(
            if (isMuted) R.drawable.ic_mic_off else R.drawable.ic_mic_on
        )
    }

    private fun toggleCamera() {
        isCameraOff = !isCameraOff
        localVideoTrack?.setEnabled(!isCameraOff)
        binding.btnToggleCamera.setImageResource(
            if (isCameraOff) R.drawable.ic_cam_off else R.drawable.ic_cam_on
        )
    }

    private fun switchCamera() {
        // Camera switcher — cast capturer if needed; simplified here
    }

    private fun endCall() {
        SocketManager.endCall(callRoom)
        peerConnection?.close()
        peerConnection = null
        finish()
    }

    override fun onDestroy() {
        super.onDestroy()
        peerConnection?.close()
        localStream?.dispose()
        peerConnectionFactory?.dispose()
        eglBase?.release()
        SocketManager.off("webrtc_offer")
        SocketManager.off("webrtc_answer")
        SocketManager.off("webrtc_ice_candidate")
        SocketManager.off("call_ended")
        SocketManager.off("call_rejected")
    }
}
