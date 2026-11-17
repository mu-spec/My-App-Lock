import 'package:flutter/material.dart';

/// F-KEY-1 owner decision G-7: neutral copy for "the credential state could
/// not be read" (secure storage / master key unavailable).
///
/// It never claims credentials are missing, never offers credential setup or
/// reset, and never implies access: the only actions are retrying the read
/// or leaving. Protection stays in force (the native shield is untouched).
abstract final class SecureStorageUnavailableText {
  static const String title = 'Secure storage unavailable';
  static const String message =
      'Secure storage is temporarily unavailable. Your protected apps remain '
      'locked. Please try again.';
  static const String retryLabel = 'Try again';
}

/// Inline banner (Security tab) shown while the credential state is
/// unreadable.
class SecureStorageUnavailableBanner extends StatelessWidget {
  const SecureStorageUnavailableBanner({super.key});

  static const Key bannerKey = ValueKey<String>('secure_storage_unavailable');

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    return Semantics(
      container: true,
      child: Card(
        key: bannerKey,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              const Icon(Icons.lock_outline),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    Text(SecureStorageUnavailableText.title,
                        style: theme.textTheme.titleSmall),
                    const SizedBox(height: 4),
                    Text(SecureStorageUnavailableText.message,
                        style: theme.textTheme.bodyMedium),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
