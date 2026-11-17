package com.smartapplock.app

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import com.smartapplock.app.NotificationPrivacyEngine.Importance
import com.smartapplock.app.NotificationPrivacyEngine.LockScreen
import com.smartapplock.app.NotificationPrivacyEngine.Placeholder
import com.smartapplock.app.NotificationPrivacyPolicy.Mode

/**
 * Phase 14 / M2: posts the neutral placeholders described by
 * [NotificationPrivacyEngine.placeholderFor]. Only the generic fields of the
 * [Placeholder] are used; nothing from the original notification exists here.
 * Placeholders are silent (low / min importance, no sound or vibration) and
 * local-only (not bridged to wearables).
 */
object NotificationPlaceholders {
    /** Same id for every placeholder; the opaque tag makes it one per app.
     * Distinct from the protection service notification (id 7, no tag). */
    const val NOTIFICATION_ID = 0x5A11

    private fun manager(context: Context): NotificationManager? =
        context.getSystemService(NotificationManager::class.java)

    private fun ensureChannels(manager: NotificationManager) {
        if (Build.VERSION.SDK_INT < 26) return
        manager.createNotificationChannel(
            NotificationChannel(
                NotificationPrivacyEngine.CHANNEL_HIDDEN,
                "Hidden notifications",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Placeholders for protected apps set to Hide content"
                setSound(null, null)
                enableVibration(false)
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            },
        )
        manager.createNotificationChannel(
            NotificationChannel(
                NotificationPrivacyEngine.CHANNEL_MAXIMUM,
                "Private notifications",
                NotificationManager.IMPORTANCE_MIN,
            ).apply {
                description = "Placeholders for protected apps set to Maximum privacy"
                setSound(null, null)
                enableVibration(false)
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            },
        )
    }

    private fun channelFor(mode: Mode): String =
        if (mode == Mode.MAXIMUM) NotificationPrivacyEngine.CHANNEL_MAXIMUM else NotificationPrivacyEngine.CHANNEL_HIDDEN

    /** Smart App Lock may post placeholders for [mode] (all modes when null). */
    fun canPost(context: Context, mode: Mode?): Boolean = try {
        val manager = manager(context)
        when {
            manager == null -> false
            Build.VERSION.SDK_INT >= 33 &&
                context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
                PackageManager.PERMISSION_GRANTED -> false
            !manager.areNotificationsEnabled() -> false
            Build.VERSION.SDK_INT >= 26 -> {
                ensureChannels(manager)
                val channels = if (mode == null) listOf(Mode.HIDE_CONTENT, Mode.MAXIMUM) else listOf(mode)
                channels.all {
                    (manager.getNotificationChannel(channelFor(it))?.importance ?: NotificationManager.IMPORTANCE_NONE) !=
                        NotificationManager.IMPORTANCE_NONE
                }
            }
            else -> true
        }
    } catch (_: Exception) {
        false
    }

    private fun builder(context: Context, p: Placeholder): Notification.Builder {
        val b = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(context, p.channelId)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(context).setDefaults(0).setPriority(
                if (p.importance == Importance.MIN) Notification.PRIORITY_MIN else Notification.PRIORITY_LOW,
            )
        }
        return b.setSmallIcon(android.R.drawable.ic_lock_lock).setShowWhen(true).setLocalOnly(true)
    }

    fun post(context: Context, p: Placeholder): Boolean = try {
        val manager = manager(context) ?: return false
        ensureChannels(manager)
        val b = builder(context, p)
            .setContentTitle(p.title)
            .setOnlyAlertOnce(true)
            .setAutoCancel(true)
            .setVisibility(
                if (p.lockScreen == LockScreen.SECRET) Notification.VISIBILITY_SECRET else Notification.VISIBILITY_PRIVATE,
            )
        if (p.text != null) b.setContentText(p.text)
        if (p.publicTitle != null) {
            b.setPublicVersion(builder(context, p).setContentTitle(p.publicTitle).build())
        }
        tapIntent(context, p)?.let { b.setContentIntent(it) }
        manager.notify(p.tag, NOTIFICATION_ID, b.build())
        true
    } catch (_: Exception) {
        false
    }

    /** Opens the protected app's own launcher activity (the existing lock
     * challenges it); never an activity of Smart App Lock, never the original
     * notification's intent or actions. */
    private fun tapIntent(context: Context, p: Placeholder): PendingIntent? {
        val launch = context.packageManager.getLaunchIntentForPackage(p.sourcePackage) ?: return null
        val target = launch.component?.packageName ?: launch.`package`
        if (!NotificationPrivacyEngine.tapTargetAllowed(context.packageName, p.sourcePackage, target)) return null
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return PendingIntent.getActivity(
            context,
            p.tag.hashCode(),
            launch,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }
}
