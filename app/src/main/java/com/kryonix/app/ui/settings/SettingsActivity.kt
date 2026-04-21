package com.kryonix.app.ui.settings

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.MediaStore
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.bumptech.glide.Glide
import com.kryonix.app.BuildConfig
import com.kryonix.app.KryonixApplication
import com.kryonix.app.api.NetworkClient
import com.kryonix.app.databinding.ActivitySettingsBinding
import com.kryonix.app.models.ThemeRequest
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.asRequestBody
import java.io.File

class SettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySettingsBinding
    private var myUsername = ""

    private val pickImageLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri -> uploadProfilePicture(uri) }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "Settings"

        lifecycleScope.launch {
            myUsername = (application as KryonixApplication).sessionManager.getUsername() ?: ""
            loadSettings()
        }

        binding.ivAvatar.setOnClickListener {
            val intent = Intent(Intent.ACTION_PICK, MediaStore.Images.Media.EXTERNAL_CONTENT_URI)
            pickImageLauncher.launch(intent)
        }

        binding.btnSaveAccount.setOnClickListener { saveAccount() }
        binding.btnChangePassword.setOnClickListener { changePassword() }

        // Theme buttons
        binding.btnThemeKryonix.setOnClickListener { setTheme("kryonix") }
        binding.btnThemeDark.setOnClickListener    { setTheme("dark")    }
        binding.btnThemeLight.setOnClickListener   { setTheme("light")   }
    }

    private fun loadSettings() {
        lifecycleScope.launch {
            try {
                val response = NetworkClient.api.getSettings()
                if (response.isSuccessful) {
                    val data = response.body() ?: return@launch
                    binding.etUsername.setText(data.username)
                    binding.etEmail.setText(data.email)
                    binding.tvCurrentTheme.text = "Current: ${data.active_theme}"

                    val picUrl = data.profile_picture
                    if (!picUrl.isNullOrEmpty()) {
                        Glide.with(this@SettingsActivity)
                            .load(BuildConfig.BASE_URL + picUrl)
                            .circleCrop()
                            .into(binding.ivAvatar)
                    }
                }
            } catch (e: Exception) {
                toast("Failed to load settings")
            }
        }
    }

    private fun saveAccount() {
        val newUsername = binding.etUsername.text.toString().trim()
        val newEmail    = binding.etEmail.text.toString().trim()
        lifecycleScope.launch {
            try {
                val response = NetworkClient.api.updateAccount(
                    username = newUsername.ifEmpty { null },
                    email    = newEmail.ifEmpty { null }
                )
                toast(if (response.isSuccessful) "Account updated!" else "Failed to update.")
            } catch (e: Exception) {
                toast("Error: ${e.localizedMessage}")
            }
        }
    }

    private fun changePassword() {
        val current = binding.etCurrentPassword.text.toString()
        val new     = binding.etNewPassword.text.toString()
        if (current.isEmpty() || new.isEmpty()) { toast("Fill in both password fields"); return }
        if (new.length < 6) { toast("New password must be at least 6 characters"); return }

        lifecycleScope.launch {
            try {
                val response = NetworkClient.api.updateAccount(
                    currentPassword = current,
                    newPassword     = new
                )
                toast(if (response.isSuccessful) "Password changed!" else "Failed.")
            } catch (e: Exception) {
                toast("Error: ${e.localizedMessage}")
            }
        }
    }

    private fun setTheme(theme: String) {
        lifecycleScope.launch {
            try {
                NetworkClient.api.setTheme(ThemeRequest(theme))
                binding.tvCurrentTheme.text = "Current: $theme"
                toast("Theme set to $theme")
            } catch (e: Exception) {
                toast("Failed to set theme")
            }
        }
    }

    private fun uploadProfilePicture(uri: Uri) {
        lifecycleScope.launch {
            try {
                val stream   = contentResolver.openInputStream(uri) ?: return@launch
                val tempFile = File.createTempFile("pfp_", ".jpg", cacheDir)
                tempFile.outputStream().use { stream.copyTo(it) }

                val reqBody  = tempFile.asRequestBody("image/*".toMediaTypeOrNull())
                val part     = MultipartBody.Part.createFormData("file", tempFile.name, reqBody)
                val response = NetworkClient.api.uploadProfilePicture(part)

                if (response.isSuccessful) {
                    Glide.with(this@SettingsActivity).load(uri).circleCrop().into(binding.ivAvatar)
                    toast("Profile picture updated!")
                } else {
                    toast("Upload failed.")
                }
                tempFile.delete()
            } catch (e: Exception) {
                toast("Error: ${e.localizedMessage}")
            }
        }
    }

    private fun toast(msg: String) =
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { onBackPressedDispatcher.onBackPressed(); return true }
        return super.onOptionsItemSelected(item)
    }
}
