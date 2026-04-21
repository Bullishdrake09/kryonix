package com.kryonix.app.ui.chat

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.MenuItem
import android.view.View
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.kryonix.app.KryonixApplication
import com.kryonix.app.R
import com.kryonix.app.api.NetworkClient
import com.kryonix.app.api.SocketManager
import com.kryonix.app.databinding.ActivityChatBinding
import com.kryonix.app.models.ChatMessage
import com.kryonix.app.models.ReplyTo
import com.kryonix.app.ui.calls.CallActivity
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject

class ChatActivity : AppCompatActivity() {

    private lateinit var binding: ActivityChatBinding
    private lateinit var messagesAdapter: MessagesAdapter
    private val messages = mutableListOf<ChatMessage>()

    private var roomId   = ""
    private var roomType = "direct"
    private var roomName = ""
    private var myUsername = ""
    private var replyingTo: ChatMessage? = null
    private var typingJob: Job? = null
    private var offset = 0
    private var hasMore = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityChatBinding.inflate(layoutInflater)
        setContentView(binding.root)

        roomId   = intent.getStringExtra("room_id")   ?: ""
        roomType = intent.getStringExtra("room_type")  ?: "direct"
        roomName = intent.getStringExtra("room_name")  ?: roomId

        setSupportActionBar(binding.toolbar)
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(true)
            title = if (roomType == "group") "# $roomName" else roomName
        }

        lifecycleScope.launch {
            myUsername = (application as KryonixApplication).sessionManager.getUsername() ?: ""
            setupUI()
            loadHistory()
            connectSocket()
        }
    }

    private fun setupUI() {
        messagesAdapter = MessagesAdapter(
            messages, myUsername,
            onLongClick = { msg -> showMessageOptions(msg) },
            onReplyClick = { msg ->
                replyingTo = msg
                binding.replyContainer.visibility = View.VISIBLE
                binding.tvReplyPreview.text = "${msg.username}: ${msg.msg.replace(Regex("<[^>]+>"), "").take(80)}"
            }
        )
        binding.rvMessages.apply {
            layoutManager = LinearLayoutManager(this@ChatActivity).apply {
                stackFromEnd = true
            }
            adapter = messagesAdapter
        }

        binding.ibCancelReply.setOnClickListener {
            replyingTo = null
            binding.replyContainer.visibility = View.GONE
        }

        binding.ibSend.setOnClickListener { sendMessage() }

        binding.etMessage.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) {
                if (!s.isNullOrEmpty()) {
                    SocketManager.sendTypingStart(roomId)
                    typingJob?.cancel()
                    typingJob = lifecycleScope.launch {
                        delay(1500)
                        SocketManager.sendTypingStop(roomId)
                    }
                } else {
                    typingJob?.cancel()
                    SocketManager.sendTypingStop(roomId)
                }
            }
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        })

        // Load more on scroll to top
        binding.rvMessages.addOnScrollListener(object : androidx.recyclerview.widget.RecyclerView.OnScrollListener() {
            override fun onScrolled(rv: androidx.recyclerview.widget.RecyclerView, dx: Int, dy: Int) {
                val lm = rv.layoutManager as LinearLayoutManager
                if (lm.findFirstVisibleItemPosition() == 0 && hasMore) {
                    loadHistory(loadMore = true)
                }
            }
        })

        // Call button — only for direct chats
        if (roomType == "direct") {
            binding.ibCall.visibility = View.VISIBLE
            binding.ibCall.setOnClickListener {
                showCallTypeDialog()
            }
        } else {
            binding.ibCall.visibility = View.GONE
        }
    }

    private fun loadHistory(loadMore: Boolean = false) {
        lifecycleScope.launch {
            try {
                val currentOffset = if (loadMore) offset else 0
                val response = NetworkClient.api.getHistory(roomId, currentOffset, 50)
                if (response.isSuccessful) {
                    val body = response.body() ?: return@launch
                    val fetched = body.messages.map { it.copy(isOwn = it.username == myUsername) }
                    if (loadMore) {
                        messages.addAll(0, fetched)
                        messagesAdapter.notifyItemRangeInserted(0, fetched.size)
                    } else {
                        messages.clear()
                        messages.addAll(fetched)
                        messagesAdapter.notifyDataSetChanged()
                        scrollToBottom()
                    }
                    offset     = currentOffset + fetched.size
                    hasMore    = body.has_more
                }
            } catch (_: Exception) {}
        }
    }

    private fun connectSocket() {
        SocketManager.connect()
        SocketManager.joinRoom(roomId)

        SocketManager.on("message") { args ->
            val data = args[0] as? JSONObject ?: return@on
            val msg = ChatMessage(
                id       = data.optString("id"),
                username = data.optString("username"),
                msg      = data.optString("msg"),
                time     = data.optString("time"),
                room     = data.optString("room"),
                isOwn    = data.optString("username") == myUsername
            )
            if (msg.room == roomId) {
                runOnUiThread {
                    messages.add(msg)
                    messagesAdapter.notifyItemInserted(messages.size - 1)
                    scrollToBottom()
                }
            }
        }

        SocketManager.on("message_updated") { args ->
            val data = args[0] as? JSONObject ?: return@on
            val id      = data.optString("id")
            val newText = data.optString("new_text")
            runOnUiThread {
                val idx = messages.indexOfFirst { it.id == id }
                if (idx >= 0) {
                    messages[idx] = messages[idx].copy(msg = newText)
                    messagesAdapter.notifyItemChanged(idx)
                }
            }
        }

        SocketManager.on("user_typing") { args ->
            val data = args[0] as? JSONObject ?: return@on
            val typingUser = data.optString("username")
            val isTyping   = data.optBoolean("is_typing")
            if (typingUser != myUsername) {
                runOnUiThread {
                    binding.tvTyping.visibility = if (isTyping) View.VISIBLE else View.GONE
                    if (isTyping) binding.tvTyping.text = "$typingUser is typing…"
                }
            }
        }

        SocketManager.on("error") { args ->
            val data = args[0] as? JSONObject ?: return@on
            runOnUiThread {
                binding.tvTyping.visibility = View.GONE
                androidx.appcompat.app.AlertDialog.Builder(this)
                    .setMessage(data.optString("message", "An error occurred."))
                    .setPositiveButton("OK", null)
                    .show()
            }
        }
    }

    private fun sendMessage() {
        val text = binding.etMessage.text.toString().trim()
        if (text.isEmpty()) return

        val replyData = replyingTo?.let {
            JSONObject().apply {
                put("id", it.id)
                put("username", it.username)
                put("msg", it.msg.replace(Regex("<[^>]+>"), "").take(200))
            }
        }

        SocketManager.sendMessage(roomId, text, replyData)
        binding.etMessage.setText("")
        replyingTo = null
        binding.replyContainer.visibility = View.GONE
    }

    private fun showMessageOptions(msg: ChatMessage) {
        val options = mutableListOf("Reply")
        if (msg.isOwn) {
            options.add("Edit")
            options.add("Delete")
        }
        AlertDialog.Builder(this)
            .setItems(options.toTypedArray()) { _, which ->
                when (options[which]) {
                    "Reply"  -> {
                        replyingTo = msg
                        binding.replyContainer.visibility = View.VISIBLE
                        binding.tvReplyPreview.text = "${msg.username}: ${msg.msg.replace(Regex("<[^>]+>"), "").take(80)}"
                    }
                    "Edit"   -> showEditDialog(msg)
                    "Delete" -> SocketManager.deleteMessage(msg.id, roomId)
                }
            }.show()
    }

    private fun showEditDialog(msg: ChatMessage) {
        val et = android.widget.EditText(this).apply {
            setText(msg.msg.replace(Regex("<[^>]+>"), ""))
        }
        AlertDialog.Builder(this)
            .setTitle("Edit message")
            .setView(et)
            .setPositiveButton("Save") { _, _ ->
                val newText = et.text.toString().trim()
                if (newText.isNotEmpty()) SocketManager.editMessage(msg.id, newText, roomId)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showCallTypeDialog() {
        AlertDialog.Builder(this)
            .setTitle("Start a call")
            .setItems(arrayOf("Video call", "Voice call")) { _, which ->
                val callType = if (which == 0) "video" else "audio"
                val callRoom = "${myUsername}_${roomName}_${System.currentTimeMillis()}"
                SocketManager.callUser(roomName, callRoom, callType)
                startActivity(Intent(this, CallActivity::class.java).apply {
                    putExtra("mode", "outgoing")
                    putExtra("callee", roomName)
                    putExtra("room", callRoom)
                    putExtra("call_type", callType)
                })
            }.show()
    }

    private fun scrollToBottom() {
        if (messages.isNotEmpty())
            binding.rvMessages.smoothScrollToPosition(messages.size - 1)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { onBackPressedDispatcher.onBackPressed(); return true }
        return super.onOptionsItemSelected(item)
    }

    override fun onDestroy() {
        super.onDestroy()
        SocketManager.leaveRoom(roomId)
        SocketManager.off("message")
        SocketManager.off("message_updated")
        SocketManager.off("user_typing")
        SocketManager.off("error")
    }
}
