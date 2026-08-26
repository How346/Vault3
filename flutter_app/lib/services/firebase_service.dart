import 'package:flutter/foundation.dart';
import 'push_service.dart';

/// Backward-compatible push service facade.
///
/// This project uses OneSignal for remote push notifications. Firebase
/// Messaging is intentionally not used directly by the Flutter application.
class FirebaseService {
  FirebaseService._();

  static final FirebaseService instance = FirebaseService._();

  bool _initialized = false;

  Future<void> init() async {
    if (_initialized) return;
    try {
      await PushService.instance.init();
      _initialized = true;
    } catch (error, stackTrace) {
      debugPrint('Push initialization failed: $error');
      debugPrintStack(stackTrace: stackTrace);
    }
  }

  Future<String?> getToken() => PushService.instance.getPlayerId();

  Future<String?> getPlayerId() => PushService.instance.getPlayerId();

  Future<void> setUserId(String id) async {
    final value = id.trim();
    if (value.isEmpty) return;
    await PushService.instance.setExternalUserId(value);
  }

  Future<void> clearUserId() => PushService.instance.clearExternalUserId();
}
