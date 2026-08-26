import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

import '../utils/constants.dart';

/// PIN + biometric gate. The PIN is never stored in plaintext.
class SecurityService {
  SecurityService._();
  static final SecurityService instance = SecurityService._();

  final _secure = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );
  final _auth = LocalAuthentication();

  static const int _kdfIterations = 120000;

  Future<bool> hasPin() async =>
      (await _secure.read(key: SecureKeys.pinHash)) != null;

  Future<void> setPin(String pin) async {
    if (!RegExp(r'^\d{4}$').hasMatch(pin)) {
      throw ArgumentError('PIN must be exactly 4 digits.');
    }
    final salt = _randomSalt();
    await _secure.write(key: SecureKeys.pinSalt, value: salt);
    await _secure.write(
      key: SecureKeys.pinHash,
      value: _derivePinHash(pin, salt),
    );
    await _secure.write(key: SecureKeys.pinKdfVersion, value: '2');
  }

  Future<bool> verifyPin(String pin) async {
    if (!RegExp(r'^\d{4}$').hasMatch(pin)) return false;
    final salt = await _secure.read(key: SecureKeys.pinSalt);
    final stored = await _secure.read(key: SecureKeys.pinHash);
    if (salt == null || stored == null) return false;

    final version = await _secure.read(key: SecureKeys.pinKdfVersion);
    if (version == '2') {
      return _constantTimeEquals(_derivePinHash(pin, salt), stored);
    }

    // Upgrade hashes created by older builds after a successful unlock.
    final legacyOk = _constantTimeEquals(_legacyHash(pin, salt), stored);
    if (legacyOk) {
      await _secure.write(
        key: SecureKeys.pinHash,
        value: _derivePinHash(pin, salt),
      );
      await _secure.write(key: SecureKeys.pinKdfVersion, value: '2');
    }
    return legacyOk;
  }

  Future<void> clearPin() async {
    await _secure.delete(key: SecureKeys.pinHash);
    await _secure.delete(key: SecureKeys.pinSalt);
    await _secure.delete(key: SecureKeys.pinKdfVersion);
  }

  Future<bool> biometricAvailable() async {
    try {
      if (!await _auth.isDeviceSupported()) return false;
      if (!await _auth.canCheckBiometrics) return false;
      return (await _auth.getAvailableBiometrics()).isNotEmpty;
    } catch (_) {
      return false;
    }
  }

  Future<bool> authenticateBiometric({
    String reason = 'Unlock your document wallet',
  }) async {
    try {
      return await _auth.authenticate(
        localizedReason: reason,
        options: const AuthenticationOptions(
          biometricOnly: true,
          stickyAuth: true,
          useErrorDialogs: true,
        ),
      );
    } catch (_) {
      return false;
    }
  }

  String _legacyHash(String pin, String salt) =>
      sha256.convert(utf8.encode('$salt::$pin')).toString();

  String _derivePinHash(String pin, String salt) {
    final key = utf8.encode(salt);
    var block = utf8.encode('DocWallet-PIN-v2:$pin');
    final hmac = Hmac(sha256, key);
    var digest = hmac.convert(block).bytes;
    for (var i = 1; i < _kdfIterations; i++) {
      digest = hmac.convert(digest).bytes;
    }
    return 'v2:${base64UrlEncode(digest)}';
  }

  bool _constantTimeEquals(String a, String b) {
    final aa = utf8.encode(a);
    final bb = utf8.encode(b);
    var diff = aa.length ^ bb.length;
    final length = aa.length < bb.length ? aa.length : bb.length;
    for (var i = 0; i < length; i++) {
      diff |= aa[i] ^ bb[i];
    }
    return diff == 0;
  }

  String _randomSalt() {
    final rnd = Random.secure();
    return base64Url.encode(List<int>.generate(24, (_) => rnd.nextInt(256)));
  }
}
