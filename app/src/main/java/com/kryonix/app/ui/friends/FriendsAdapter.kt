package com.kryonix.app.ui.friends

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.kryonix.app.R

class FriendsAdapter(
    private val items: List<String>,
    private val mode: String,           // "friend" | "request" | "blocked"
    private val onAccept:  ((String) -> Unit)? = null,
    private val onDecline: ((String) -> Unit)? = null,
    private val onMore:    ((String) -> Unit)? = null
) : RecyclerView.Adapter<FriendsAdapter.VH>() {

    inner class VH(view: View) : RecyclerView.ViewHolder(view) {
        val tvName:    TextView    = view.findViewById(R.id.tvName)
        val btnAccept: ImageButton = view.findViewById(R.id.btnAccept)
        val btnDecline: ImageButton = view.findViewById(R.id.btnDecline)
        val btnMore:   ImageButton = view.findViewById(R.id.btnMore)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH =
        VH(LayoutInflater.from(parent.context).inflate(R.layout.item_friend, parent, false))

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        val name = items[position]
        holder.tvName.text = name

        when (mode) {
            "request" -> {
                holder.btnAccept.visibility  = View.VISIBLE
                holder.btnDecline.visibility = View.VISIBLE
                holder.btnMore.visibility    = View.GONE
                holder.btnAccept.setOnClickListener  { onAccept?.invoke(name)  }
                holder.btnDecline.setOnClickListener { onDecline?.invoke(name) }
            }
            else -> {
                holder.btnAccept.visibility  = View.GONE
                holder.btnDecline.visibility = View.GONE
                holder.btnMore.visibility    = View.VISIBLE
                holder.btnMore.setOnClickListener { onMore?.invoke(name) }
            }
        }
    }
}
