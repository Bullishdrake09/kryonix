package com.kryonix.app.models

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

// ── Auth ────────────────────────────────────────────────

data class LoginRequest(
    val login_field: String,
    val password: String
)

data class RegisterRequest(
    val username: String,
    val email: String,
    val password: String
)

data class VerifyCodeRequest(
    val code: String
)

data class AuthResponse(
    val success: Boolean = false,
    val error: String? = null,
    val message: String? = null,
    val username: String? = null,
    val redirect: String? = null,
    // For 2FA flows
    val requires_2fa: Boolean = false,
    val masked_email: String? = null
)

// ── User / Profile ───────────────────────────────────────

@Parcelize
data class UserProfile(
    val username: String,
    val email: String = "",
    val profile_picture: String? = null,
    val status: String = "offline",
    val active_theme: String = "kryonix"
) : Parcelable

data class UserSettings(
    val primary_color: String = "#0f0f0f",
    val accent_color: String = "#ff3f81"
)

// ── Contacts / Friends ───────────────────────────────────

data class FriendsResponse(
    val friends: List<String> = emptyList(),
    val requests: List<String> = emptyList(),
    val blocked: List<String> = emptyList()
)

data class FriendActionRequest(
    val action: String,           // send_request | accept_request | decline_request | remove_friend | block_user | unblock_user
    val target_username: String
)

data class GenericResponse(
    val success: Boolean = false,
    val error: String? = null,
    val ok: Boolean = false
)

// ── Messages ─────────────────────────────────────────────

@Parcelize
data class ReplyTo(
    val id: String,
    val username: String,
    val msg: String
) : Parcelable

@Parcelize
data class ChatMessage(
    val id: String,
    val username: String,
    val msg: String,
    val time: String,
    val room: String,
    val reply_to: ReplyTo? = null,
    var isOwn: Boolean = false        // set client-side
) : Parcelable

data class HistoryResponse(
    val messages: List<ChatMessage> = emptyList(),
    val total: Int = 0,
    val has_more: Boolean = false
)

// ── Groups ───────────────────────────────────────────────

@Parcelize
data class GroupChat(
    val id: String,
    val name: String,
    val members: List<String> = emptyList()
) : Parcelable

data class GroupInfo(
    val name: String,
    val creator: String,
    val members: List<MemberInfo> = emptyList(),
    val is_creator: Boolean = false
)

data class MemberInfo(
    val username: String,
    val profile_picture: String? = null
)

data class CreateGroupRequest(
    val name: String,
    val members: List<String>
)

data class CreateGroupResponse(
    val success: Boolean = false,
    val group_id: String? = null,
    val group_name: String? = null,
    val error: String? = null
)

data class GroupActionRequest(
    val action: String,
    val name: String? = null,
    val member: String? = null,
    val members: List<String>? = null
)

// ── Contacts order ───────────────────────────────────────

data class ContactItem(
    val id: String,
    val type: String,                 // "direct" | "group"
    val name: String? = null,
    val last_message_time: String? = null,
    val last_message_timestamp: Long = 0,
    val last_message_text: String = "",
    val unread_count: Int = 0
)

data class ContactsOrderResponse(
    val contacts: List<ContactItem> = emptyList()
)

// ── Settings ─────────────────────────────────────────────

data class ThemeRequest(val theme: String)

data class UserSettingsData(
    val email: String = "",
    val username: String = "",
    val profile_picture: String? = null,
    val sound_message: String? = null,
    val sound_calling: String? = null,
    val active_theme: String = "kryonix",
    val custom_css_url: String? = null
)

// ── WebRTC / Calls ───────────────────────────────────────

data class CallInfo(
    val callee: String,
    val room: String,
    val type: String                  // "video" | "audio"
)

// ── FCM ──────────────────────────────────────────────────

data class FcmTokenRequest(
    val token: String
)

// ── Profiles bulk fetch ───────────────────────────────────

data class ProfilesRequest(val usernames: List<String>)
// response is Map<String, ProfileInfo>

data class ProfileInfo(val profile_picture: String? = null)

// ── Pending friend requests count ────────────────────────

data class PendingCountResponse(val count: Int = 0)
