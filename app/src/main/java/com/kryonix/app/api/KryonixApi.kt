package com.kryonix.app.api

import com.kryonix.app.models.*
import okhttp3.MultipartBody
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.*

interface KryonixApi {

    // ── Auth ──────────────────────────────────────────────────────

    @POST("api/login")
    suspend fun login(@Body body: LoginRequest): Response<AuthResponse>

    @POST("api/register")
    suspend fun register(@Body body: RegisterRequest): Response<AuthResponse>

    @POST("api/verify-email")
    suspend fun verifyEmail(@Body body: VerifyCodeRequest): Response<AuthResponse>

    @GET("api/verify-email/resend")
    suspend fun resendVerifyEmail(): Response<GenericResponse>

    @POST("api/verify-login")
    suspend fun verifyLogin(@Body body: VerifyCodeRequest): Response<AuthResponse>

    @GET("api/verify-login/resend")
    suspend fun resendLoginCode(): Response<GenericResponse>

    @GET("api/logout")
    suspend fun logout(): Response<GenericResponse>

    // ── User / Profile ────────────────────────────────────────────

    @GET("api/me")
    suspend fun getMe(): Response<UserProfile>

    @GET("api/settings")
    suspend fun getSettings(): Response<UserSettingsData>

    @POST("api/settings/account")
    @FormUrlEncoded
    suspend fun updateAccount(
        @Field("username") username: String? = null,
        @Field("email") email: String? = null,
        @Field("current_password") currentPassword: String? = null,
        @Field("new_password") newPassword: String? = null
    ): Response<GenericResponse>

    @POST("api/settings/theme")
    suspend fun setTheme(@Body body: ThemeRequest): Response<GenericResponse>

    @Multipart
    @POST("api/upload_profile_picture")
    suspend fun uploadProfilePicture(
        @Part file: MultipartBody.Part
    ): Response<GenericResponse>

    @POST("api/upload_profile_picture")
    suspend fun removeProfilePicture(@Body body: Map<String, Boolean>): Response<GenericResponse>

    // ── Friends ───────────────────────────────────────────────────

    @GET("api/friends")
    suspend fun getFriends(): Response<FriendsResponse>

    @POST("api/friends")
    suspend fun friendAction(@Body body: FriendActionRequest): Response<GenericResponse>

    @GET("api/get_pending_requests_count")
    suspend fun getPendingCount(): Response<PendingCountResponse>

    @POST("api/get_user_profiles")
    suspend fun getUserProfiles(@Body body: ProfilesRequest): Response<Map<String, ProfileInfo>>

    // ── Contacts order ────────────────────────────────────────────

    @GET("api/get_contacts_order")
    suspend fun getContactsOrder(): Response<ContactsOrderResponse>

    // ── History ───────────────────────────────────────────────────

    @GET("api/history/{room}")
    suspend fun getHistory(
        @Path("room") room: String,
        @Query("offset") offset: Int = 0,
        @Query("limit") limit: Int = 50
    ): Response<HistoryResponse>

    // ── Groups ────────────────────────────────────────────────────

    @POST("api/create_group")
    suspend fun createGroup(@Body body: CreateGroupRequest): Response<CreateGroupResponse>

    @GET("api/get_group_info/{group_id}")
    suspend fun getGroupInfo(@Path("group_id") groupId: String): Response<GroupInfo>

    @POST("api/update_group/{group_id}")
    suspend fun updateGroup(
        @Path("group_id") groupId: String,
        @Body body: GroupActionRequest
    ): Response<GenericResponse>

    // ── File uploads ──────────────────────────────────────────────

    @Multipart
    @POST("api/upload_file")
    suspend fun uploadFile(
        @Part file: MultipartBody.Part
    ): Response<UploadResponse>

    // ── FCM token registration ────────────────────────────────────

    @POST("api/register_fcm_token")
    suspend fun registerFcmToken(@Body body: FcmTokenRequest): Response<GenericResponse>
}

data class UploadResponse(val url: String? = null, val error: String? = null)
