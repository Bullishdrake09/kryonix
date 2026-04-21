package com.kryonix.app.ui.auth

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.kryonix.app.KryonixApplication
import com.kryonix.app.api.NetworkClient
import com.kryonix.app.databinding.ActivityVerifyCodeBinding
import com.kryonix.app.models.VerifyCodeRequest
import kotlinx.coroutines.launch

class VerifyLoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityVerifyCodeBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityVerifyCodeBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val maskedEmail = intent.getStringExtra("masked_email") ?: ""
        binding.tvTitle.text = "Login Verification"
        binding.tvSubtitle.text = "Enter the 6-digit code sent to $maskedEmail"

        binding.btnVerify.setOnClickListener { verify() }
        binding.tvResend.setOnClickListener { resend() }
    }

    private fun verify() {
        val code = binding.etCode.text.toString().trim()
        if (code.length != 6) { showError("Enter the 6-digit code."); return }

        setLoading(true)
        lifecycleScope.launch {
            try {
                val response = NetworkClient.api.verifyLogin(VerifyCodeRequest(code))
                if (response.isSuccessful) {
                    val body = response.body()
                    when {
                        body?.error != null -> showError(body.error)
                        body?.success == true -> {
                            val session = (application as KryonixApplication).sessionManager
                            session.saveUsername(body.username ?: "")
                            session.clearPending2FA()
                            startActivity(
                                Intent(this@VerifyLoginActivity,
                                    com.kryonix.app.ui.chat.MainActivity::class.java)
                                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                            finish()
                        }
                        else -> showError("Unexpected response.")
                    }
                } else {
                    showError("Server error ${response.code()}")
                }
            } catch (e: Exception) {
                showError("Network error: ${e.localizedMessage}")
            } finally {
                setLoading(false)
            }
        }
    }

    private fun resend() {
        lifecycleScope.launch {
            try {
                NetworkClient.api.resendLoginCode()
                binding.tvError.text = "New code sent."
                binding.tvError.setTextColor(getColor(com.kryonix.app.R.color.success))
                binding.tvError.visibility = View.VISIBLE
            } catch (e: Exception) {
                showError("Failed to resend.")
            }
        }
    }

    private fun showError(msg: String) {
        binding.tvError.text = msg
        binding.tvError.setTextColor(getColor(com.kryonix.app.R.color.error))
        binding.tvError.visibility = View.VISIBLE
    }

    private fun setLoading(loading: Boolean) {
        binding.btnVerify.isEnabled = !loading
        binding.progressBar.visibility = if (loading) View.VISIBLE else View.GONE
    }
}
