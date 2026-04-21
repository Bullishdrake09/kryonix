package com.kryonix.app.ui.friends

import android.os.Bundle
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.kryonix.app.api.NetworkClient
import com.kryonix.app.databinding.ActivityFriendsBinding
import com.kryonix.app.models.FriendActionRequest
import kotlinx.coroutines.launch

class FriendsActivity : AppCompatActivity() {

    private lateinit var binding: ActivityFriendsBinding
    private var friends  = listOf<String>()
    private var requests = listOf<String>()
    private var blocked  = listOf<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityFriendsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "Friends"

        binding.btnSendRequest.setOnClickListener {
            val target = binding.etSearchUser.text.toString().trim()
            if (target.isEmpty()) return@setOnClickListener
            doAction("send_request", target)
        }

        loadFriends()
    }

    private fun loadFriends() {
        lifecycleScope.launch {
            try {
                val response = NetworkClient.api.getFriends()
                if (response.isSuccessful) {
                    val body = response.body() ?: return@launch
                    friends  = body.friends
                    requests = body.requests
                    blocked  = body.blocked
                    updateUI()
                }
            } catch (e: Exception) {
                Toast.makeText(this@FriendsActivity, "Error: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun updateUI() {
        // Pending requests section
        binding.tvRequestsHeader.visibility = if (requests.isNotEmpty()) View.VISIBLE else View.GONE
        binding.rvRequests.visibility       = if (requests.isNotEmpty()) View.VISIBLE else View.GONE

        binding.rvRequests.layoutManager = LinearLayoutManager(this)
        binding.rvRequests.adapter = FriendsAdapter(requests, "request",
            onAccept = { doAction("accept_request", it) },
            onDecline = { doAction("decline_request", it) },
            onMore = { showMoreOptions(it, "request") }
        )

        // Friends list
        binding.rvFriends.layoutManager = LinearLayoutManager(this)
        binding.rvFriends.adapter = FriendsAdapter(friends, "friend",
            onMore = { showMoreOptions(it, "friend") }
        )

        binding.tvEmptyFriends.visibility = if (friends.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun showMoreOptions(target: String, type: String) {
        val options = when (type) {
            "friend"  -> arrayOf("Remove friend", "Block")
            "request" -> arrayOf("Accept", "Decline")
            else      -> arrayOf("Unblock")
        }
        AlertDialog.Builder(this)
            .setTitle(target)
            .setItems(options) { _, i ->
                when (options[i]) {
                    "Remove friend" -> doAction("remove_friend", target)
                    "Block"         -> doAction("block_user", target)
                    "Accept"        -> doAction("accept_request", target)
                    "Decline"       -> doAction("decline_request", target)
                    "Unblock"       -> doAction("unblock_user", target)
                }
            }.show()
    }

    private fun doAction(action: String, target: String) {
        lifecycleScope.launch {
            try {
                val response = NetworkClient.api.friendAction(FriendActionRequest(action, target))
                val body     = response.body()
                val msg      = body?.error ?: "Done"
                Toast.makeText(this@FriendsActivity, msg, Toast.LENGTH_SHORT).show()
                if (body?.success == true || body?.ok == true) loadFriends()
            } catch (e: Exception) {
                Toast.makeText(this@FriendsActivity, "Error: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { onBackPressedDispatcher.onBackPressed(); return true }
        return super.onOptionsItemSelected(item)
    }
}
