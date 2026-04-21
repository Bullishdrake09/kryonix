package com.kryonix.app.utils

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.map

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "kryonix_session")

class SessionManager(private val context: Context) {

    companion object {
        private val KEY_USERNAME = stringPreferencesKey("username")
        private val KEY_FCM_TOKEN = stringPreferencesKey("fcm_token")
        private val KEY_PENDING_2FA = stringPreferencesKey("pending_2fa")  // "login" | "register" | ""
        private val KEY_MASKED_EMAIL = stringPreferencesKey("masked_email")
    }

    val usernameFlow: Flow<String?> = context.dataStore.data
        .map { it[KEY_USERNAME] }

    suspend fun saveUsername(username: String) {
        context.dataStore.edit { it[KEY_USERNAME] = username }
    }

    suspend fun getUsername(): String? =
        context.dataStore.data.firstOrNull()?.get(KEY_USERNAME)

    suspend fun clearSession() {
        context.dataStore.edit { it.clear() }
    }

    suspend fun isLoggedIn(): Boolean = getUsername() != null

    suspend fun saveFcmToken(token: String) {
        context.dataStore.edit { it[KEY_FCM_TOKEN] = token }
    }

    suspend fun getFcmToken(): String? =
        context.dataStore.data.firstOrNull()?.get(KEY_FCM_TOKEN)

    suspend fun setPending2FA(type: String, maskedEmail: String) {
        context.dataStore.edit {
            it[KEY_PENDING_2FA]  = type
            it[KEY_MASKED_EMAIL] = maskedEmail
        }
    }

    suspend fun getPending2FA(): Pair<String, String> {
        val prefs       = context.dataStore.data.firstOrNull()
        val type        = prefs?.get(KEY_PENDING_2FA) ?: ""
        val maskedEmail = prefs?.get(KEY_MASKED_EMAIL) ?: ""
        return Pair(type, maskedEmail)
    }

    suspend fun clearPending2FA() {
        context.dataStore.edit {
            it.remove(KEY_PENDING_2FA)
            it.remove(KEY_MASKED_EMAIL)
        }
    }
}
