package com.smartapplock.app

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import java.lang.ref.WeakReference

/**
 * Entry Activity of the Smart App Lock application.
 *
 * Extends [FlutterFragmentActivity] (instead of FlutterActivity) because
 * the biometric integration (Phase 2J, `local_auth`) requires a
 * FragmentActivity host for the AndroidX BiometricPrompt on a range of
 * API levels — the prompt is attached via a Fragment. This is the
 * officially recommended host for apps using local_auth.
 *
 * Native bridges (Phase 3A: the installed-apps PackageManager channel) are
 * registered in [configureFlutterEngine].
 *
 * Later phases will add sibling Android components (e.g.
 * [android.app.admin.DeviceAdminReceiver] and
 * [android.accessibilityservice.AccessibilityService] subclasses) for the
 * app-lock enforcement features.
 */
class MainActivity : FlutterFragmentActivity() {

    /** Phase 6 / M2: package of the ticket pending at the last onPause. */
    private var pendingPackageAtPause: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        // Phase 6 / M1 review: must run before super.onCreate, which is where
        // the Flutter embedding reads launch extras from getIntent().
        setIntent(sanitizedLaunchIntent(intent))
        super.onCreate(savedInstanceState)
        currentActivity = WeakReference(this)
        acceptRecoveryIntent(intent, "onCreate")
    }

    override fun onResume() {
        // Set this before Flutter receives the resumed lifecycle. A Dart
        // post-frame ready acknowledgement issued from that callback must
        // never be rejected because native state was one callback behind.
        ProtectionRuntime.activityResumed = true
        ProtectionRuntime.activityInMultiWindow = isInMultiWindowMode
        super.onResume()
        currentActivity = WeakReference(this)
        // Phase 6 / M2: our own UI (no pending ticket) is a foreground change;
        // a resume into multi-window with a pending ticket keeps the shield.
        WatcherService.onOwnUiResumed(this, pendingPackageAtPause)
        pendingPackageAtPause = null
        WatcherService.onChallengeActivityMultiWindow(this, isInMultiWindowMode)
        acceptRecoveryIntent(intent, "onResume")
        WatcherService.onChallengeActivityAvailable(this)
    }

    /**
     * Phase 6 / M2: entering split screen / freeform while a challenge is
     * pending re-raises the shield (see [MultiWindowChallengePolicy]). The
     * one-argument form is overridden because it is the variant Android
     * calls on every supported API level (24+); on API 26+ the two-argument
     * framework method delegates to it.
     */
    @Deprecated("Deprecated in Java")
    @Suppress("DEPRECATION")
    override fun onMultiWindowModeChanged(isInMultiWindowMode: Boolean) {
        super.onMultiWindowModeChanged(isInMultiWindowMode)
        ProtectionRuntime.activityInMultiWindow = isInMultiWindowMode
        WatcherService.onChallengeActivityMultiWindow(this, isInMultiWindowMode)
    }

    override fun onNewIntent(intent: Intent) {
        val launch = sanitizedLaunchIntent(intent)
        super.onNewIntent(launch)
        setIntent(launch)
        acceptRecoveryIntent(launch, "onNewIntent")
        // singleTop/reorder-to-front may deliver a new intent without
        // recreating Flutter. Keep the native retry path armed while the
        // existing host pulls and reconstructs its pending challenge.
        WatcherService.onChallengeActivityAvailable(this)
    }

    override fun onPause() {
        ProtectionRuntime.activityResumed = false
        // Phase 12 / M2: the camera and alarm never outlive the foreground.
        IntruderEvidenceChannel.onActivityPaused()
        // H-1 F1: confirms a leave reported just before this pause.
        WatcherService.onChallengeActivityPaused(this)
        pendingPackageAtPause = ProtectionStateStore.pendingChallenge(this)?.packageName
        super.onPause()
    }

    override fun onDestroy() {
        ProtectionRuntime.activityResumed = false
        IntruderEvidenceChannel.onActivityDestroyed()
        ProtectionRuntime.activityInMultiWindow = false
        // Phase 6 / M3 (R-M3-2): the engine's screen-off revocation goes away
        // with this Activity. Without a running watcher receiver no session
        // may outlive it (fail closed); tickets and the shield are untouched.
        if (WatcherTeardownPolicy.revokesOnEngineDetach(
                protectionEnabled = ProtectionStateStore.isEnabled(this),
                watcherRunning = WatcherService.isRunning(),
            )
        ) {
            ProtectionAccessState.revokeAll()
        }
        if (currentActivity?.get() === this) {
            currentActivity = null
        }
        super.onDestroy()
    }

    /**
     * Phase 6 / M1 (Alternate Entry Paths): this Activity is exported (it is
     * the launcher entry), so any app, launcher shortcut or `am start` can
     * send it an explicit intent with arbitrary data and extras. By default
     * the Flutter embedding turns Intent data into a pushed route (deep
     * linking is enabled unless the manifest opts out) and reads the `route`
     * extra as the initial route, which lets an external caller drive this
     * app's navigator, for example push a setup or diagnostics screen above
     * an active lock challenge.
     *
     * External intents never choose a destination here: deep linking is off
     * and the initial route is always the shell. Challenge routing comes only
     * from the native pending ticket; ACTION_RECOVER_CHALLENGE is matched
     * against that ticket in [acceptRecoveryIntent] and can only re-raise the
     * shield, never authorize. The Dart side ignores platform route pushes as
     * defense in depth (`ExternalRouteGuard`, `AppRouter.onGenerateInitialRoutes`).
     */
    override fun shouldHandleDeeplinking(): Boolean = false

    /**
     * Phase 6 / M1 review: rebuilds an external launch Intent so the Flutter
     * embedding never sees caller-supplied data or extras. Those include
     * `cached_engine_id`, `cached_engine_group_id`, `background_mode`,
     * `dart_entrypoint_args`, `route` and the shell arguments such as
     * `dart-flags`. A malformed value would otherwise throw during startup
     * and kill the whole process, watcher and Accessibility service included.
     * Only the action is kept, plus the two recovery extras for
     * [ACTION_RECOVER_CHALLENGE] (see [LaunchIntentPolicy]). Our own
     * [foregroundForRecovery] path sets its trusted Intent directly.
     */
    private fun sanitizedLaunchIntent(source: Intent?): Intent {
        val retained = LaunchIntentPolicy.retain(
            action = source?.action,
            recoveryAction = ACTION_RECOVER_CHALLENGE,
            readRecoveryPackage = { source?.getStringExtra(EXTRA_PACKAGE_NAME) },
            readRecoveryGeneration = {
                source?.getLongExtra(EXTRA_GENERATION, -1L) ?: -1L
            },
        )
        return Intent(this, MainActivity::class.java).apply {
            action = retained.action
            retained.recoveryPackage?.let { putExtra(EXTRA_PACKAGE_NAME, it) }
            retained.recoveryGeneration?.let { putExtra(EXTRA_GENERATION, it) }
        }
    }

    override fun getInitialRoute(): String = INITIAL_ROUTE

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        InstalledAppsChannel.register(flutterEngine, this)
        AccessibilityStatusChannel.register(flutterEngine, this)
        OverlayStatusChannel.register(flutterEngine, this)
        ScreenStateChannel.register(flutterEngine, this)
        WatcherChannel.register(flutterEngine, this)
        // Phase 14 / M1: notification privacy (package names + mode ids only).
        NotificationPrivacyChannel.register(flutterEngine, this)
        // Phase 12 / M2: owner-opted-in intruder evidence + alarm.
        IntruderEvidenceChannel.register(flutterEngine, this)
        // Phase 13 / M3 Batch 2: AndroidKeyStore KEK for the data key.
        KeyWrapChannel.register(flutterEngine)
    }

    /**
     * Phase 17 / M2 (R3): Flutter does not cancel EventChannel streams when
     * an engine is destroyed, so the static Accessibility sink installed by
     * this engine is released here. Owner-checked: a newer engine's sink is
     * never cleared. Native enforcement does not use this sink.
     */
    override fun cleanUpFlutterEngine(flutterEngine: FlutterEngine) {
        AccessibilityLockService.releaseEventSink(flutterEngine)
        super.cleanUpFlutterEngine(flutterEngine)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        if (IntruderEvidenceChannel.onRequestPermissionsResult(this, requestCode, grantResults)) {
            return
        }
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
    }

    private fun acceptRecoveryIntent(intent: Intent?, callback: String) {
        if (intent?.action != ACTION_RECOVER_CHALLENGE) return
        val packageName = intent.getStringExtra(EXTRA_PACKAGE_NAME) ?: return
        val generation = intent.getLongExtra(EXTRA_GENERATION, -1L)
        val pending = ProtectionStateStore.pendingChallenge(this)
        val exact = RecoveryIntentPolicy.matches(pending, packageName, generation)
        DiagLog.d(this, TAG) {
            "$callback recovery package=$packageName generation=$generation exact=$exact"
        }
        if (exact) {
            WatcherService.onChallengeActivityAvailable(this)
        }
    }

    companion object {
        private const val TAG = "SmartAppLockActivity"
        /** The shell route (`RouteNames.home`); see [getInitialRoute]. */
        private const val INITIAL_ROUTE = "/"
        const val ACTION_RECOVER_CHALLENGE =
            "com.smartapplock.app.action.RECOVER_CHALLENGE"
        const val EXTRA_PACKAGE_NAME = "protectedPackageName"
        const val EXTRA_GENERATION = "challengeGeneration"

        @Volatile private var currentActivity: WeakReference<MainActivity>? = null

        fun recoveryIntent(
            context: Context,
            challenge: ProtectionStateStore.PendingChallenge,
        ): Intent = Intent(context, MainActivity::class.java).apply {
            action = ACTION_RECOVER_CHALLENGE
            putExtra(EXTRA_PACKAGE_NAME, challenge.packageName)
            putExtra(EXTRA_GENERATION, challenge.generation)
            addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP,
            )
        }

        /**
         * Raises the exact existing Flutter task when it is still alive.
         * MainActivity has an empty task affinity as task-hijacking hardening,
         * so a plain NEW_TASK launch cannot be relied on to find that task.
         * If no live Activity exists, the explicit recovery intent cold-starts
         * one. Neither path clears the pending shield latch.
         */
        /**
         * Phase 17 / M1 (observational): which hand-off path
         * [foregroundForRecovery] is about to take. Read-only; never used
         * for enforcement.
         */
        fun recoveryLaunchMode(): LatencyLaunchMode = try {
            val activity = currentActivity?.get()?.takeUnless {
                it.isFinishing || it.isDestroyed
            }
            when {
                activity == null -> LatencyLaunchMode.COLD_START
                ProtectionRuntime.activityResumed -> LatencyLaunchMode.RESUMED
                else -> LatencyLaunchMode.TASK_TO_FRONT
            }
        } catch (_: Exception) {
            LatencyLaunchMode.UNKNOWN
        }

        fun foregroundForRecovery(
            context: Context,
            challenge: ProtectionStateStore.PendingChallenge,
        ): Boolean {
            val recoveryIntent = recoveryIntent(context, challenge)
            val activity = currentActivity?.get()?.takeUnless {
                it.isFinishing || it.isDestroyed
            }
            if (activity != null) {
                return try {
                    // Deliver the generation even when Android elects not to
                    // call onNewIntent for a task promotion. Flutter consumes
                    // it only after the Activity actually resumes.
                    activity.setIntent(recoveryIntent)
                    activity.acceptRecoveryIntent(recoveryIntent, "existingTask")
                    val manager = activity.getSystemService(ActivityManager::class.java)
                    manager.moveTaskToFront(
                        activity.taskId,
                        ActivityManager.MOVE_TASK_WITH_HOME,
                    )
                    DiagLog.d(context, TAG) {
                        "moveTaskToFront taskId=${activity.taskId} " +
                            "package=${challenge.packageName} " +
                            "generation=${challenge.generation}"
                    }
                    true
                } catch (e: Exception) {
                    DiagLog.w(context, TAG, e) { "Existing task promotion failed" }
                    launchCold(context, recoveryIntent, challenge)
                }
            }
            return launchCold(context, recoveryIntent, challenge)
        }

        private fun launchCold(
            context: Context,
            intent: Intent,
            challenge: ProtectionStateStore.PendingChallenge,
        ): Boolean = try {
            context.startActivity(intent)
            DiagLog.d(context, TAG) {
                "startActivity package=${challenge.packageName} " +
                    "generation=${challenge.generation}"
            }
            true
        } catch (e: Exception) {
            DiagLog.w(context, TAG, e) { "Recovery Activity launch failed" }
            false
        }
    }
}
