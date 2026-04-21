package com.kryonix.app.ui.chat

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.kryonix.app.KryonixApplication
import com.kryonix.app.R
import com.kryonix.app.api.NetworkClient
import com.kryonix.app.api.SocketManager
import com.kryonix.app.databinding.ActivityMainBinding
import com.kryonix.app.models.ContactItem
import com.kryonix.app.services.SocketService
import com.kryonix.app.ui.friends.FriendsActivity
import com.kryonix.app.ui.settings.SettingsActivity
import kotlinx.coroutines.launch
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var contactsAdapter: ContactsAdapter
    private val contacts = mutableListOf<ContactItem>()
    private var myUsername = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        supportActionBar?.title = "Kryonix"

        lifecycleScope.launch {
            myUsername = (application as KryonixApplication).sessionManager.getUsername() ?: ""
        }

        setupRecyclerView()
        startSocketService()
        connectSocket()
        loadContacts()
        setupFab()

        binding.swipeRefresh.setOnRefreshListener { loadContacts() }
    }

    private fun setupRecyclerView() {
        contactsAdapter = ContactsAdapter(contacts, myUsername) { contact ->
            val intent = Intent(this, ChatActivity::class.java).apply {
                putExtra("room_id", contact.id)
                putExtra("room_type", contact.type)
                putExtra("room_name", if (contact.type == "group") contact.name else contact.id)
            }
            startActivity(intent)
        }
        binding.rvContacts.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = contactsAdapter
        }
    }

    private fun loadContacts() {
        lifecycleScope.launch {
            try {
                binding.swipeRefresh.isRefreshing = true
                val response = NetworkClient.api.getContactsOrder()
                if (response.isSuccessful) {
                    val items = response.body()?.contacts ?: emptyList()
                    contacts.clear()
                    contacts.addAll(items)
                    contactsAdapter.notifyDataSetChanged()
                    binding.tvEmpty.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
                }
            } catch (_: Exception) {
            } finally {
                binding.swipeRefresh.isRefreshing = false
            }
        }
    }

    private fun startSocketService() {
        val intent = Intent(this, SocketService::class.java)
        startService(intent)
    }

    private fun connectSocket() {
        SocketManager.connect()
        SocketManager.announceConnected()
        SocketManager.requestStatuses()

        // Listen for incoming calls
        SocketManager.on("incoming_call") { args ->
            val data = args[0] as? JSONObject ?: return@on
            val caller   = data.optString("caller")
            val room     = data.optString("room")
            val callType = data.optString("type", "video")
            runOnUiThread {
                val intent = Intent(this, com.kryonix.app.ui.calls.CallActivity::class.java).apply {
                    putExtra("mode", "incoming")
                    putExtra("caller", caller)
                    putExtra("room", room)
                    putExtra("call_type", callType)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                startActivity(intent)
            }
        }

        // Friend-related socket updates — just refresh the list
        SocketManager.on("friend_request_received") { _ -> runOnUiThread { loadContacts() } }
        SocketManager.on("friend_request_accepted") { _ -> runOnUiThread { loadContacts() } }
        SocketManager.on("friend_removed")          { _ -> runOnUiThread { loadContacts() } }
        SocketManager.on("group_membership_update") { _ -> runOnUiThread { loadContacts() } }
    }

    private fun setupFab() {
        binding.fabNewChat.setOnClickListener {
            startActivity(Intent(this, FriendsActivity::class.java))
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_friends  -> { startActivity(Intent(this, FriendsActivity::class.java)); true }
            R.id.action_settings -> { startActivity(Intent(this, SettingsActivity::class.java)); true }
            R.id.action_logout   -> { logout(); true }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun logout() {
        lifecycleScope.launch {
            try { NetworkClient.api.logout() } catch (_: Exception) {}
            NetworkClient.clearCookies()
            SocketManager.disconnect()
            (application as KryonixApplication).sessionManager.clearSession()
            startActivity(
                Intent(this@MainActivity, com.kryonix.app.ui.auth.LoginActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK or Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        }
    }

    override fun onResume() {
        super.onResume()
        loadContacts()
    }

    override fun onDestroy() {
        super.onDestroy()
        SocketManager.off("incoming_call")
        SocketManager.off("friend_request_received")
        SocketManager.off("friend_request_accepted")
        SocketManager.off("friend_removed")
        SocketManager.off("group_membership_update")
    }
}
