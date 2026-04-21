package com.kryonix.app.ui.auth

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.kryonix.app.KryonixApplication
import com.kryonix.app.api.NetworkClient
import com.kryonix.app.databinding.ActivityLoginBinding
import com.kryonix.app.models.LoginRequest
import kotlinx.coroutines.launch

class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnLogin.setOnClickListener { attemptLogin() }
        binding.tvRegister.setOnClickListener {
            startActivity(Intent(this, RegisterActivity::class.java))
        }
    }

    private fun attemptLogin() {
        val loginField = binding.etLoginField.text.toString().trim()
        val password   = binding.etPassword.text.toString()

        if (loginField.isEmpty() || password.isEmpty()) {
            showError("Please fill in all fields.")
            return
        }

        setLoading(true)
        lifecycleScope.launch {
            try {
                val response = NetworkClient.api.login(LoginRequest(loginField, password))
                if (response.isSuccessful) {
                    val body = response.body()
                    when {
                        body?.error != null -> showError(body.error)
                        body?.requires_2fa == true -> {
                            // Server set session cookie for 2FA; navigate to verify screen
                            val session = (application as KryonixApplication).sessionManager
                            session.setPending2FA("login", body.masked_email ?: "")
                            startActivity(Intent(this@LoginActivity, VerifyLoginActivity::class.java)
                                .putExtra("masked_email", body.masked_email ?: ""))
                            finish()
                        }
                        body?.success == true -> {
                            val session = (application as KryonixApplication).sessionManager
                            session.saveUsername(body.username ?: loginField)
                            startActivity(Intent(this@LoginActivity,
                                com.kryonix.app.ui.chat.MainActivity::class.java))
                            finish()
                        }
                        else -> showError("Unexpected response from server.")
                    }
                } else {
                    showError("Server error: ${response.code()}")
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
        binding.btnLogin.isEnabled = !loading
        binding.progressBar.visibility = if (loading) View.VISIBLE else View.GONE
        binding.tvError.visibility = View.GONE
    }
}
