package com.kryonix.app.ui.chat

import android.text.format.DateUtils
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.bumptech.glide.Glide
import com.kryonix.app.BuildConfig
import com.kryonix.app.R
import com.kryonix.app.models.ContactItem
import java.text.SimpleDateFormat
import java.util.*

class ContactsAdapter(
    private val items: List<ContactItem>,
    private val myUsername: String,
    private val onClick: (ContactItem) -> Unit
) : RecyclerView.Adapter<ContactsAdapter.VH>() {

    inner class VH(view: View) : RecyclerView.ViewHolder(view) {
        val avatar: ImageView = view.findViewById(R.id.ivAvatar)
        val name: TextView    = view.findViewById(R.id.tvName)
        val preview: TextView = view.findViewById(R.id.tvPreview)
        val time: TextView    = view.findViewById(R.id.tvTime)
        val badge: TextView   = view.findViewById(R.id.tvBadge)
        val indicator: View   = view.findViewById(R.id.onlineIndicator)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH =
        VH(LayoutInflater.from(parent.context).inflate(R.layout.item_contact, parent, false))

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        val item = items[position]

        // Display name
        val displayName = if (item.type == "group") "# ${item.name ?: item.id}"
                          else item.id
        holder.name.text = displayName

        // Avatar initials fallback
        val initial = displayName.firstOrNull()?.uppercase() ?: "?"
        holder.avatar.contentDescription = initial

        // Glide avatar — for direct chats we load profile pic from API base
        val picUrl = "${BuildConfig.BASE_URL}/profile_pics/${item.id}.jpg"
        Glide.with(holder.itemView)
            .load(if (item.type == "direct") picUrl else null)
            .placeholder(R.drawable.ic_avatar_placeholder)
            .circleCrop()
            .into(holder.avatar)

        // Preview text — strip HTML tags
        val raw = item.last_message_text
        val stripped = raw.replace(Regex("<[^>]+>"), "").take(60)
        holder.preview.text = if (stripped.isNotEmpty()) stripped else "No messages yet"

        // Timestamp
        holder.time.text = if (item.last_message_timestamp > 0)
            formatTimestamp(item.last_message_timestamp) else ""

        // Unread badge
        if (item.unread_count > 0) {
            holder.badge.text = item.unread_count.toString()
            holder.badge.visibility = View.VISIBLE
        } else {
            holder.badge.visibility = View.GONE
        }

        // Online indicator (only for direct)
        holder.indicator.visibility = if (item.type == "direct") View.VISIBLE else View.GONE

        holder.itemView.setOnClickListener { onClick(item) }
    }

    private fun formatTimestamp(ts: Long): String {
        val now = System.currentTimeMillis()
        return when {
            DateUtils.isToday(ts) -> {
                val sdf = SimpleDateFormat("HH:mm", Locale.getDefault())
                sdf.format(Date(ts))
            }
            now - ts < 7 * 24 * 60 * 60 * 1000L -> {
                val sdf = SimpleDateFormat("EEE", Locale.getDefault())
                sdf.format(Date(ts))
            }
            else -> {
                val sdf = SimpleDateFormat("dd/MM/yy", Locale.getDefault())
                sdf.format(Date(ts))
            }
        }
    }
}
