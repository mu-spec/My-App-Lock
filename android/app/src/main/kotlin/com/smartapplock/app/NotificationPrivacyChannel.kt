package com.smartapplock.app

import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Phase 14 / M1: Flutter bridge for notification privacy. It carries
 * package names and mode ids only. No notification content ever crosses
 * this channel.
 */
object NotificationPrivacyChannel {
    const val CHANNEL = "smart_app_lock/notification_privacy"

    fun register(engine: FlutterEngine, activity: MainActivity) {
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                try {
                    when (call.method) {
                        "getStatus" -> result.success(status(activity))
                        "configure" -> {
                            val modes = NotificationPrivacyPolicy.normalize(call.argument<Map<*, *>>("modes"))
                            val applied = modes != null && NotificationPrivacyStore.configure(activity, modes)
                            if (applied) SalNotificationListenerService.refreshBinding(activity)
                            result.success(mapOf("applied" to applied, "count" to (modes?.size ?: 0)))
                        }
                        "openAccessSettings" -> result.success(openAccessSettings(activity))
                        "openOwnNotificationSettings" -> result.success(openOwnNotificationSettings(activity))
                        "openAppNotificationSettings" -> result.success(
                            openAppNotificationSettings(activity, call.argument<String>("packageName")),
                        )
                        else -> result.notImplemented()
                    }
                } catch (e: Exception) {
                    result.error("notification_privacy_error", e.javaClass.simpleName, null)
                }
            }
    }

    private fun status(context: Context): Map<String, Any> {
        val snapshot = NotificationPrivacyStore.read(context)
        return mapOf(
            "accessGranted" to accessGranted(context),
            "listenerConnected" to SalNotificationListenerService.connected,
            "storeInvalid" to snapshot.invalid,
            "configuredCount" to snapshot.modes.size,
            // M2: placeholders can be shown (POST_NOTIFICATIONS, app
            // notifications and both placeholder channels enabled).
            "placeholdersAllowed" to NotificationPlaceholders.canPost(context, null),
        )
    }

    fun accessGranted(context: Context): Boolean = try {
        val component = SalNotificationListenerService.component(context)
        if (Build.VERSION.SDK_INT >= 27) {
            context.getSystemService(NotificationManager::class.java)
                ?.isNotificationListenerAccessGranted(component) == true
        } else {
            NotificationPrivacyPolicy.listenerEnabledIn(
                Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners"),
                context.packageName,
                component.className,
            )
        }
    } catch (_: Exception) {
        false
    }

    private fun openAccessSettings(activity: MainActivity): Boolean {
        for (action in NotificationPrivacyPolicy.accessSettingsActions(Build.VERSION.SDK_INT)) {
            try {
                val intent = Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                if (action == NotificationPrivacyPolicy.ACTION_LISTENER_DETAIL_SETTINGS) {
                    intent.putExtra(
                        NotificationPrivacyPolicy.EXTRA_LISTENER_COMPONENT,
                        SalNotificationListenerService.component(activity).flattenToString(),
                    )
                }
                activity.startActivity(intent)
                return true
            } catch (_: Exception) {
                // Try the next allowlisted screen.
            }
        }
        return false
    }

    /** M2: Smart App Lock's own notification settings (to allow placeholders). */
    private fun openOwnNotificationSettings(activity: MainActivity): Boolean =
        startFirst(activity, appNotificationSettingsIntents(activity.packageName))

    private fun appNotificationSettingsIntents(pkg: String): List<Intent> = buildList {
        if (Build.VERSION.SDK_INT >= 26) {
            add(
                Intent(ProtectionSettingsTargets.ACTION_APP_NOTIFICATION_SETTINGS)
                    .putExtra(ProtectionSettingsTargets.EXTRA_APP_PACKAGE, pkg),
            )
        }
        add(
            Intent(ProtectionSettingsTargets.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(Uri.fromParts("package", pkg, null)),
        )
    }

    private fun startFirst(activity: MainActivity, attempts: List<Intent>): Boolean {
        for (intent in attempts) {
            try {
                activity.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                return true
            } catch (_: Exception) {
                // Fall back to App info.
            }
        }
        return false
    }

    private fun openAppNotificationSettings(activity: MainActivity, packageName: String?): Boolean {
        if (!NotificationPrivacyPolicy.mayOpenAppNotificationSettings(
                packageName,
                ProtectionStateStore.protectedPackages(activity),
            )
        ) {
            return false
        }
        val pkg = packageName!!
        val attempts = buildList {
            if (Build.VERSION.SDK_INT >= 26) {
                add(
                    Intent(ProtectionSettingsTargets.ACTION_APP_NOTIFICATION_SETTINGS)
                        .putExtra(ProtectionSettingsTargets.EXTRA_APP_PACKAGE, pkg),
                )
            }
            add(
                Intent(ProtectionSettingsTargets.ACTION_APPLICATION_DETAILS_SETTINGS)
                    .setData(Uri.fromParts("package", pkg, null)),
            )
        }
        for (intent in attempts) {
            try {
                activity.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                return true
            } catch (_: Exception) {
                // Fall back to App info.
            }
        }
        return false
    }
}
