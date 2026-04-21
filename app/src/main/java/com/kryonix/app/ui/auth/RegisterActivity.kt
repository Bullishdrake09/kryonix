package com.kryonix.app.ui.auth

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.kryonix.app.KryonixApplication
import com.kryonix.app.api.NetworkClient
import com.kryonix.app.databinding.ActivityRegisterBinding
import com.kryonix.app.models.RegisterRequest
import kotlinx.coroutines.launch

class RegisterActivity : AppCompatActivity() {

    private lateinit var binding: ActivityRegisterBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityRegisterBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnRegister.setOnClickListener { attemptRegister() }
        binding.tvLogin.setOnClickListener { finish() }
    }

    private fun attemptRegister() {
        val username = binding.etUsername.text.toString().trim()
        val email    = binding.etEmail.text.toString().trim().lowercase()
        val password = binding.etPassword.text.toString()
        val confirm  = binding.etConfirmPassword.text.toString()

        if (username.isEmpty() || email.isEmpty() || password.isEmpty()) {
            showError("All fields are required."); return
        }
        if (username.length < 3) {
            showError("Username must be at least 3 characters."); return
        }
        if (!username.matches(Regex("^[\\w.\\-]+$"))) {
            showError("Username may only contain letters, numbers, dots, dashes, underscores."); return
        }
        if (!email.contains("@")) {
            showError("Invalid email."); return
        }
        if (password.length < 6) {
            showError("Password must be at least 6 characters."); return
        }
        if (password != confirm) {
            showError("Passwords do not match."); return
        }

        setLoading(true)
        lifecycleScope.launch {
            try {
                val response = NetworkClient.api.register(RegisterRequest(username, email, password))
                if (response.isSuccessful) {
                    val body = response.body()
                    when {
                        body?.error != null -> showError(body.error)
                        body?.success == true || body?.redirect == "verify_email" -> {
                            val session = (application as KryonixApplication).sessionManager
                            session.setPending2FA("register", body.masked_email ?: "")
                            startActivity(
                                Intent(this@RegisterActivity, VerifyEmailActivity::class.java)
                                    .putExtra("masked_email", body.masked_email ?: "")
                            )
                            finish()
                        }
                        else -> showError("Unexpected server response.")
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

    private fun showError(msg: String) {
        binding.tvError.text = msg
        binding.tvError.visibility = View.VISIBLE
    }

    private fun setLoading(loading: Boolean) {
        binding.btnRegister.isEnabled = !loading
        binding.progressBar.visibility = if (loading) View.VISIBLE else View.GONE
        binding.tvError.visibility = View.GONE
    }
}
