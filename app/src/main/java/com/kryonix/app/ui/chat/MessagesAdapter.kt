package com.kryonix.app.ui.chat

import android.text.Html
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.constraintlayout.widget.ConstraintLayout
import androidx.recyclerview.widget.RecyclerView
import com.kryonix.app.R
import com.kryonix.app.models.ChatMessage

class MessagesAdapter(
    private val items: List<ChatMessage>,
    private val myUsername: String,
    private val onLongClick: (ChatMessage) -> Unit,
    private val onReplyClick: (ChatMessage) -> Unit
) : RecyclerView.Adapter<MessagesAdapter.VH>() {

    companion object {
        private const val VIEW_TYPE_OUTGOING = 1
        private const val VIEW_TYPE_INCOMING = 2
    }

    override fun getItemViewType(position: Int) =
        if (items[position].isOwn) VIEW_TYPE_OUTGOING else VIEW_TYPE_INCOMING

    inner class VH(view: View) : RecyclerView.ViewHolder(view) {
        val tvMessage: TextView    = view.findViewById(R.id.tvMessage)
        val tvUsername: TextView   = view.findViewById(R.id.tvUsername)
        val tvTime: TextView       = view.findViewById(R.id.tvTime)
        val replyBar: View         = view.findViewById(R.id.replyBar)
        val tvReplyText: TextView  = view.findViewById(R.id.tvReplyText)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val layout = if (viewType == VIEW_TYPE_OUTGOING)
            R.layout.item_message_outgoing else R.layout.item_message_incoming
        return VH(LayoutInflater.from(parent.context).inflate(layout, parent, false))
    }

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        val msg = items[position]

        // Render HTML (for <em>deleted message</em> etc.)
        holder.tvMessage.text = Html.fromHtml(msg.msg, Html.FROM_HTML_MODE_COMPACT)
        holder.tvTime.text    = msg.time

        // Show sender name for group chats
        if (!msg.isOwn) {
            holder.tvUsername.text       = msg.username
            holder.tvUsername.visibility = View.VISIBLE
        } else {
            holder.tvUsername.visibility = View.GONE
        }

        // Reply preview
        val reply = msg.reply_to
        if (reply != null) {
            holder.replyBar.visibility = View.VISIBLE
            holder.tvReplyText.text    = "${reply.username}: ${reply.msg.replace(Regex("<[^>]+>"), "").take(80)}"
        } else {
            holder.replyBar.visibility = View.GONE
        }

        holder.itemView.setOnLongClickListener { onLongClick(msg); true }
        holder.replyBar.setOnClickListener { onReplyClick(msg) }
    }
}
