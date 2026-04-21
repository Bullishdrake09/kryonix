package com.kryonix.app

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import com.kryonix.app.api.NetworkClient
import com.kryonix.app.utils.SessionManager

class KryonixApplication : Application() {

    lateinit var sessionManager: SessionManager
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        NetworkClient.init(this)
        sessionManager = SessionManager(this)
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)

            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_MESSAGES,
                    getString(R.string.channel_messages_name),
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = getString(R.string.channel_messages_desc)
                    enableVibration(true)
                }
            )

            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_CALLS,
                    getString(R.string.channel_calls_name),
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = getString(R.string.channel_calls_desc)
                    enableVibration(true)
                }
            )

            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_SOCKET_SERVICE,
                    "Background sync",
                    NotificationManager.IMPORTANCE_LOW
                )
            )
        }
    }

    companion object {
        const val CHANNEL_MESSAGES       = "kryonix_messages"
        const val CHANNEL_CALLS          = "kryonix_calls"
        const val CHANNEL_SOCKET_SERVICE = "kryonix_socket_service"

        lateinit var instance: KryonixApplication
            private set
    }
}
