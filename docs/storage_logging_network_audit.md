# Storage, logging and network audit (Phase 18 / M2)

PRD v2.1, Phase 18 / Milestone 2. Guards:
`test/regression/p18_m2_storage_inventory_test.dart` (ST-01…10),
`p18_m2_release_logging_test.dart` (LG-01…07),
`p18_m2_network_guard_test.dart` (NW-01…07). Each store, key, table and
alias below is pinned by those tests. A new one fails them until it is
classified here.

## 1. Storage inventory

All storage is app-private (internal storage, `MODE_PRIVATE`). The app
writes no files, media or external storage (ST-07).

### 1.1 Dart preferences (`shared_preferences`), plaintext, non-secret

| Key | Content |
|---|---|
| `pref.onboarding.completed` | bool |
| `pref.theme.mode` | UI theme id |
| `pref.language.code` | language code |
| `pref.notifications.enabled` | bool |
| `pref.profile.last_active_id` | profile id |
| `pref.capability.ever_granted.` | prefix; one bool per permission kind |
| `pref.security_recommendation.dismissed` | dismissed suggestions, `package@level` per line (**package names**) |

### 1.2 Secret tier (`flutter_secure_storage`, Keystore/Tink-encrypted)

| Key | Content |
|---|---|
| `sec.settings_master_key` | 256-bit data key for the `enc:v1:` rows. It is written only by `MasterKeyResolver`. |

### 1.3 SQLite `smart_app_lock.db` (schema v2)

| Table | Columns | Encryption |
|---|---|---|
| `protected_apps` | package_name, label, added_at, sort_order, security_level | **plaintext** |
| `profiles` | id, name, description, is_active, locked_packages | **plaintext** (legacy) |
| `lock_rules` | id, type, package_name, start/end minute, max_launches, enabled | **plaintext** (legacy) |
| `security_settings` | key, value, updated_at | per row, below |

`security_settings` rows:

| Row key | Value |
|---|---|
| `security_settings` | `enc:v1:` AES-256-GCM. Holds the PBKDF2 credential hashes and salts, the lockout state and the security options. No raw PIN or pattern. |
| `sec.key_commit` | plaintext key metadata (state, key id, Keystore alias). The data key appears only as a Keystore-wrapped blob. |
| `intruder_evidence_index`, `intruder_evidence_blob_` | `enc:v1:` intruder photos and their index |
| `intruder_evidence_index.quarantine` | unreadable copy of an encrypted row |
| `intruder_defense_settings` | `enc:v1:` |
| `intruder_failure_log`, `intruder_failure_log.quarantine` | `enc:v1:` (the quarantine row keeps the unreadable ciphertext) |
| `notification_privacy_settings` | `enc:v1:` |
| `security_event_journal`, `security_event_journal.quarantine` | `enc:v1:` (same) |
| `smart_rules` | **plaintext** JSON: rule ids, times, target packages, levels |
| `security_profiles` | **plaintext** JSON: profile ids, names, per-package levels |
| `lock.grace_period_seconds` | plaintext integer |

### 1.4 Native SharedPreferences (plaintext, read on the lock path without Dart)

| File | Keys |
|---|---|
| `smart_app_lock_protection_bootstrap` | `enabled`, `protected_packages`, `security_levels`, `security_levels_version`, `smart_rules`, `smart_rules_version`, `pending_challenge`, `pending_challenge_generation`, `next_challenge_generation`, `wake_reauth_package`, `wake_reauth_boot_count`, `wake_reauth_stamp_elapsed`, `wake_reauth_stamp_wall`, `last_error`, `last_error_code` |
| `smart_app_lock_notification_privacy` | `version`, `modes` (package → Off/Hide/Maximum), `placeholder_salt` (random per-install salt; not a credential) |

### 1.5 Android Keystore aliases (non-exportable)

| Alias | Use |
|---|---|
| `sal_kek_` (prefix) | AES-256 KEK that wraps the data key (P13/M3). It is not bound to user authentication (G8). |
| `sal_bio_binding_v1` | AES-256-GCM key. It requires user authentication and is invalidated by biometric enrollment changes (F18-3). |

`flutter_secure_storage` also keeps its own Tink keyset, protected by a Keystore key it manages, plus encrypted values in its own preferences file.

### 1.6 Backup and device transfer

`android:allowBackup="false"`. `backup_rules.xml` (API 23–30) and `data_extraction_rules.xml` (API 31+, both `cloud-backup` and `device-transfer`) exclude every domain and have no include rules (BR-01…06, ST-09). Keystore keys never leave the device.

## 2. D-M2-1 — Option A (owner decision): plaintext values kept

These values stay plaintext. All of them are app-private and excluded from backup and transfer:

- **Protected apps:** `protected_apps` table, native `protected_packages`.
- **Security levels:** `protected_apps.security_level`, native `security_levels`, the `security_profiles` row.
- **Smart Rules:** the `smart_rules` row, native `smart_rules`. Legacy `lock_rules` and `profiles` tables.
- **Notification-privacy modes:** native `modes`.
- **Lock-path state:** `pending_challenge`, `wake_reauth_package`.
- **Dismissed suggestions:** the dismissed-recommendation preference (package names).

These values contain no PIN, pattern, credential hash, salt, encryption key, biometric secret or intruder evidence. ST-08 checks this in the source: none of these stores references credential, cipher, Keystore, biometric or intruder code. P18/M1 CP1–CP3 check that a raw credential is never written anywhere.

No database or native-preference encryption was added. The native lock path reads these values without Dart, so encrypting them would need a separate design and separate approval.

**Residual privacy risk (accepted, D-M2-1 A):** someone with root access, a debuggable build or physical forensic access to app-private storage can read which apps are protected. They can also read the levels, rules, profile names and notification modes. They cannot read any credential, key or evidence. Android file-based encryption protects this data while the device is locked after boot.

## 3. Logging

- **Native:** `android.util.Log` is used only in `DiagLog.kt`, which emits only in debuggable builds (RL-01…05, `ReleaseLogPolicyTest`).
- **Dart:** every `print`, `debugPrint` and `debugPrintStack` call is inside `assert(...)` or `if (kDebugMode ...)`, so release builds compile them out (LG-01). There is no `dart:developer`, `stdout` or `stderr` (LG-04). `AppLogger` is debug-only.
- **G3:** `SAL_QA_DIAG` is read once, in `lib/app/qa_diagnostics_policy.dart`: `kQaDiagnosticsEnabled = SAL_QA_DIAG && !dart.vm.product`. Release builds never emit `[SAL_QA]` lines (which contain package names), even when built with `--dart-define=SAL_QA_DIAG=true`. Debug and profile QA builds keep them (LG-02, LG-03).
- **G5 (audit only):**
  - **Framework behaviour.** Flutter's default `FlutterError.presentError` still prints `exception.toString()` and the stack in release builds. So does the engine's handler for uncaught asynchronous errors.
  - **Error texts with package names.** Only 5 Dart error texts carry a package name. Each is returned as a `Result` failure or caught, never thrown to those handlers (LG-06). The native `throw` messages are constant (LG-07).
  - **Platform channels.** Every Dart call to a platform channel catches errors or wraps them in a `Result`.
  - **No custom handler.** No global error handler or error zone is installed (LG-05). Adding one needs owner approval.
  - **Result.** No sensitive-data leak was confirmed.

## 4. Network

- **Release build has no network access.** The release (main) manifest declares no network permission. The debug and profile manifests add only `INTERNET`, which the Flutter tooling needs (NW-01).
- **No plugin adds one.** No resolved plugin manifest requests a network permission (NW-07).
- **Code:** `lib/` and the native sources use no network API (NW-02, NW-03).
- **Dependencies:** the dependencies and Gradle artifacts are pinned to the audited set, and there are no analytics or crash-reporting packages (NW-04…06).
- **Core protection has no network dependency.** It works with no connection.

## 5. Physical-device / CI QA (pending)

- Release build logcat while locking, unlocking, failing and rebooting. Look for no `[SAL_QA]` lines, package names or credential data, including a build made with `--dart-define=SAL_QA_DIAG=true`.
- Protection in airplane mode.
- `dumpsys package` shows no `INTERNET` permission on the release build.
- `processReleaseManifest` (merged release manifest) in CI.
- Inspect the prefs, database and secure storage on a debuggable build or emulator.
- `bmgr` backup and device-to-device transfer exclusion.
- Android 7–16 on Samsung, Xiaomi, Oppo and Vivo.
