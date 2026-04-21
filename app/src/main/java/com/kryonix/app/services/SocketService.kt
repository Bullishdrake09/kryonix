package com.kryonix.app.services

import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.kryonix.app.KryonixApplication
import com.kryonix.app.R
import com.kryonix.app.api.SocketManager
import com.kryonix.app.ui.chat.MainActivity

/**
 * Keeps Socket.IO connected while the app is backgrounded so the user
 * continues to receive real-time events (typing, message updates, call signalling).
 * Push notifications (FCM) handle the fully-closed case.
 */
class SocketService : Service() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIF_ID, buildNotification())
        SocketManager.connect()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        // Don't disconnect socket here — let it stay alive while process lives
    }

    private fun buildNotification() = NotificationCompat.Builder(
        this, KryonixApplication.CHANNEL_SOCKET_SERVICE
    )
        .setSmallIcon(R.drawable.ic_notification)
        .setContentTitle("Kryonix")
        .setContentText("Connected — ready for messages")
        .setPriority(NotificationCompat.PRIORITY_MIN)
        .setOngoing(true)
        .setContentIntent(
            PendingIntent.getActivity(
                this, 0, Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE
            )
        )
        .build()

    companion object {
        private const val NOTIF_ID = 9001
    }
}
