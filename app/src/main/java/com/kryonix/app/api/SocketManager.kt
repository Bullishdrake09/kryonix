package com.kryonix.app.api

import android.util.Log
import com.kryonix.app.BuildConfig
import io.socket.client.IO
import io.socket.client.Socket
import io.socket.engineio.client.transports.WebSocket
import okhttp3.OkHttpClient
import org.json.JSONObject
import java.net.URI

/**
 * Manages the Socket.IO connection lifecycle.
 * Re-uses the same OkHttpClient (with session cookie) as Retrofit so the
 * server recognises the socket connection as the logged-in user.
 */
object SocketManager {

    private const val TAG = "SocketManager"
    private var socket: Socket? = null

    fun connect() {
        if (socket?.connected() == true) return

        try {
            val options = IO.Options().apply {
                transports = arrayOf(WebSocket.NAME)
                // Pass the same OkHttp client so cookies are sent on the handshake
                callFactory = NetworkClient.okHttpClient
                webSocketFactory = NetworkClient.okHttpClient
                reconnection = true
                reconnectionAttempts = Int.MAX_VALUE
                reconnectionDelay = 1000
                reconnectionDelayMax = 5000
            }
            socket = IO.socket(URI.create(BuildConfig.SOCKET_URL), options)
            socket?.connect()
            Log.d(TAG, "Socket connecting to ${BuildConfig.SOCKET_URL}")
        } catch (e: Exception) {
            Log.e(TAG, "Socket connection failed: ${e.message}")
        }
    }

    fun disconnect() {
        socket?.disconnect()
        socket = null
    }

    fun isConnected(): Boolean = socket?.connected() == true

    // ── Room management ────────────────────────────────────────────

    fun joinRoom(room: String) {
        val data = JSONObject().put("room", room)
        emit("join", data)
    }

    fun leaveRoom(room: String) {
        val data = JSONObject().put("room", room)
        emit("leave", data)
    }

    // ── Messaging ──────────────────────────────────────────────────

    fun sendMessage(room: String, msg: String, replyTo: JSONObject? = null) {
        val data = JSONObject().apply {
            put("room", room)
            put("msg", msg)
            replyTo?.let { put("reply_to", it) }
        }
        emit("send_message", data)
    }

    fun editMessage(messageId: String, newText: String, room: String) {
        val data = JSONObject().apply {
            put("message_id", messageId)
            put("new_text", newText)
            put("room", room)
        }
        emit("edit_message", data)
    }

    fun deleteMessage(messageId: String, room: String) {
        val data = JSONObject().apply {
            put("message_id", messageId)
            put("room", room)
        }
        emit("delete_message", data)
    }

    // ── Typing ────────────────────────────────────────────────────

    fun sendTypingStart(room: String) = emit("typing_start", JSONObject().put("room", room))
    fun sendTypingStop(room: String)  = emit("typing_stop",  JSONObject().put("room", room))

    // ── Status ────────────────────────────────────────────────────

    fun requestStatuses() = emit("request_statuses", JSONObject())
    fun announceConnected() = emit("user_connected", JSONObject())

    // ── WebRTC / Calls ────────────────────────────────────────────

    fun callUser(callee: String, room: String, type: String = "video") {
        val data = JSONObject().apply {
            put("callee", callee)
            put("room", room)
            put("type", type)
        }
        emit("call_user", data)
    }

    fun answerCall(caller: String, room: String, type: String) {
        val data = JSONObject().apply {
            put("caller", caller)
            put("room", room)
            put("type", type)
        }
        emit("answer_call", data)
    }

    fun rejectCall(caller: String, room: String) {
        val data = JSONObject().apply {
            put("caller", caller)
            put("room", room)
        }
        emit("reject_call", data)
    }

    fun endCall(room: String) {
        emit("end_call", JSONObject().put("room", room))
    }

    fun sendWebRtcOffer(offer: JSONObject, room: String) {
        val data = JSONObject().apply {
            put("offer", offer)
            put("room", room)
        }
        emit("webrtc_offer", data)
    }

    fun sendWebRtcAnswer(answer: JSONObject, room: String) {
        val data = JSONObject().apply {
            put("answer", answer)
            put("room", room)
        }
        emit("webrtc_answer", data)
    }

    fun sendIceCandidate(candidate: JSONObject, room: String) {
        val data = JSONObject().apply {
            put("candidate", candidate)
            put("room", room)
        }
        emit("webrtc_ice_candidate", data)
    }

    // Group calls
    fun startGroupCall(room: String, type: String = "video") {
        val data = JSONObject().apply {
            put("room", room)
            put("type", type)
        }
        emit("group_call_start", data)
    }

    fun leaveGroupCall(callRoom: String) {
        emit("group_call_leave", JSONObject().put("call_room", callRoom))
    }

    // ── Listener registration ──────────────────────────────────────

    fun on(event: String, listener: io.socket.emitter.Emitter.Listener) {
        socket?.on(event, listener)
    }

    fun off(event: String, listener: io.socket.emitter.Emitter.Listener? = null) {
        if (listener == null) socket?.off(event) else socket?.off(event, listener)
    }

    fun off(event: String) {
        socket?.off(event)
    }

    // ── Internal ──────────────────────────────────────────────────

    private fun emit(event: String, data: JSONObject) {
        if (socket?.connected() == true) {
            socket?.emit(event, data)
        } else {
            Log.w(TAG, "Socket not connected; dropping event: $event")
        }
    }
}
