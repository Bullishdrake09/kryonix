package com.kryonix.app.services

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import com.kryonix.app.KryonixApplication
import com.kryonix.app.R
import com.kryonix.app.api.NetworkClient
import com.kryonix.app.models.FcmTokenRequest
import com.kryonix.app.ui.chat.ChatActivity
import com.kryonix.app.ui.calls.CallActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class KryonixFirebaseService : FirebaseMessagingService() {

    override fun onNewToken(token: String) {
        super.onNewToken(token)
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Save locally and register with server
                val app = application as KryonixApplication
                app.sessionManager.saveFcmToken(token)
                if (app.sessionManager.isLoggedIn()) {
                    NetworkClient.api.registerFcmToken(FcmTokenRequest(token))
                }
            } catch (_: Exception) {}
        }
    }

    override fun onMessageReceived(message: RemoteMessage) {
        super.onMessageReceived(message)
        val data = message.data

        when (data["type"]) {
            "message" -> showMessageNotification(
                sender  = data["sender"]  ?: "Someone",
                content = data["content"] ?: "New message",
                roomId  = data["room_id"] ?: "",
                roomType = data["room_type"] ?: "direct",
                roomName = data["room_name"] ?: ""
            )
            "call" -> showCallNotification(
                caller   = data["caller"]    ?: "Someone",
                callRoom = data["call_room"] ?: "",
                callType = data["call_type"] ?: "video"
            )
            "friend_request" -> showFriendRequestNotification(
                from = data["from"] ?: "Someone"
            )
        }
    }

    private fun showMessageNotification(
        sender: String, content: String,
        roomId: String, roomType: String, roomName: String
    ) {
        val intent = Intent(this, ChatActivity::class.java).apply {
            putExtra("room_id",   roomId)
            putExtra("room_type", roomType)
            putExtra("room_name", roomName)
            addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        val pi = PendingIntent.getActivity(
            this, roomId.hashCode(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, KryonixApplication.CHANNEL_MESSAGES)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(sender)
            .setContentText(content)
            .setStyle(NotificationCompat.BigTextStyle().bigText(content))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pi)
            .build()

        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(roomId.hashCode(), notification)
    }

    private fun showCallNotification(caller: String, callRoom: String, callType: String) {
        val acceptIntent = Intent(this, CallActivity::class.java).apply {
            putExtra("mode",      "incoming")
            putExtra("caller",    caller)
            putExtra("room",      callRoom)
            putExtra("call_type", callType)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val acceptPi = PendingIntent.getActivity(
            this, callRoom.hashCode(), acceptIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, KryonixApplication.CHANNEL_CALLS)
            .setSmallIcon(R.drawable.ic_call)
            .setContentTitle("Incoming ${callType} call")
            .setContentText("$caller is calling you")
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setAutoCancel(true)
            .setFullScreenIntent(acceptPi, true)
            .setContentIntent(acceptPi)
            .addAction(R.drawable.ic_call, "Answer", acceptPi)
            .build()

        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(callRoom.hashCode(), notification)
    }

    private fun showFriendRequestNotification(from: String) {
        val nm = getSystemService(NotificationManager::class.java)
        val notification = NotificationCompat.Builder(this, KryonixApplication.CHANNEL_MESSAGES)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("New friend request")
            .setContentText("$from sent you a friend request")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()
        nm.notify(from.hashCode(), notification)
    }
}
