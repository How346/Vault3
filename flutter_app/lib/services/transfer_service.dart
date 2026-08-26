import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:path/path.dart' as p;
import 'package:shelf/shelf.dart' as shelf;
import 'package:shelf/shelf_io.dart' as shelf_io;

import '../models/doc_category.dart';
import '../models/doc_item.dart';
import '../models/profile.dart';
import '../utils/constants.dart';
import 'storage_service.dart';

const int kTransferPort = 47653;
const int kMaxTransferBytes = 1024 * 1024 * 1024; // 1 GiB safety ceiling.
const int kMaxAuthFailures = 6;
const Duration kAuthBlockDuration = Duration(seconds: 20);

class TransferException implements Exception {
  TransferException(this.message);

  final String message;

  @override
  String toString() => message;
}

/// Offline device-to-device migration over the local network / hotspot.
class TransferService {
  TransferService._();

  static final TransferService instance = TransferService._();

  HttpServer? _server;
  String? _sessionToken;
  int _authFailures = 0;
  DateTime? _blockedUntil;
  bool _payloadServed = false;

  bool get isHosting => _server != null;

  // ---------------------------------------------------------------- server

  Future<String> startServer({
    required String code,
    void Function(double progress)? onProgress,
    VoidCallback? onCompleted,
  }) async {
    await stopServer();

    if (code.length != 6 || int.tryParse(code) == null) {
      throw TransferException('Invalid transfer code.');
    }

    final bindIp = await localIp();
    if (bindIp == null) {
      throw TransferException(
        'No Wi-Fi or hotspot connection found. '
        'Connect both phones to the same network.',
      );
    }

    final payload = await buildPayload();
    if (payload.length > kMaxTransferBytes) {
      throw TransferException('Transfer is too large to safely prepare.');
    }

    final sessionToken = _randomToken();
    _sessionToken = sessionToken;
    _authFailures = 0;
    _blockedUntil = null;
    _payloadServed = false;

    Future<shelf.Response> handler(shelf.Request request) async {
      if (request.method != 'GET') {
        return shelf.Response(405, body: 'method not allowed');
      }

      final path = '/${request.url.path}';
      if (path != '/handshake' && path != '/payload') {
        return shelf.Response.notFound('no');
      }

      final now = DateTime.now();
      if (_blockedUntil != null && now.isBefore(_blockedUntil!)) {
        return shelf.Response(429, body: 'temporarily blocked');
      }

      final given = request.url.queryParameters['code'] ?? '';
      if (!_constantTimeEquals(given, code)) {
        _authFailures++;
        if (_authFailures >= kMaxAuthFailures) {
          _blockedUntil = now.add(kAuthBlockDuration);
          _authFailures = 0;
        }
        return shelf.Response(401, body: 'invalid code');
      }

      // A successful handshake creates a short-lived capability token.
      // The 6-digit code alone is never sufficient to download the payload.
      if (path == '/payload') {
        if (_payloadServed) {
          return shelf.Response(410, body: 'transfer already completed');
        }
        final token = request.url.queryParameters['token'] ?? '';
        if (!_constantTimeEquals(token, sessionToken)) {
          return shelf.Response(403, body: 'invalid session');
        }
      }

      _authFailures = 0;

      if (path == '/handshake') {
        return shelf.Response.ok(
          jsonEncode({
            'app': 'wallet',
            'size': payload.length,
            'token': sessionToken,
          }),
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'no-store',
          },
        );
      }

      var sent = 0;
      const chunkSize = 64 * 1024;
      final stream = Stream<List<int>>.fromIterable(
        <List<int>>[
          for (var start = 0; start < payload.length; start += chunkSize)
            payload.sublist(
              start,
              (start + chunkSize).clamp(0, payload.length),
            ),
        ],
      ).map((chunk) {
        sent += chunk.length;
        if (payload.isNotEmpty) {
          onProgress?.call(sent / payload.length);
        }
        if (sent >= payload.length) {
          _payloadServed = true;
          onCompleted?.call();
        }
        return chunk;
      });

      return shelf.Response.ok(
        stream,
        headers: {
          'content-type': 'application/octet-stream',
          'content-length': '${payload.length}',
          'cache-control': 'no-store',
        },
      );
    }

    try {
      _server = await shelf_io.serve(
        handler,
        InternetAddress(bindIp),
        kTransferPort,
      );
      _server!.autoCompress = false;
    } on SocketException catch (e) {
      _sessionToken = null;
      throw TransferException(
        'Could not start the transfer server '
        '(${e.osError?.message ?? 'port busy'}).',
      );
    }

    return bindIp;
  }

  String _randomToken() {
    final random = Random.secure();
    final bytes = List<int>.generate(32, (_) => random.nextInt(256));
    return base64UrlEncode(bytes).replaceAll('=', '');
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

  Future<void> stopServer() async {
    final server = _server;

    _server = null;
    _sessionToken = null;
    _authFailures = 0;
    _blockedUntil = null;
    _payloadServed = false;

    if (server != null) {
      try {
        await server.close(force: true);
      } catch (_) {}
    }
  }

  // -------------------------------------------------------------- network

  static Future<String?> localIp() async {
    try {
      final interfaces = await NetworkInterface.list(
        type: InternetAddressType.IPv4,
        includeLoopback: false,
      );

      for (final interface in interfaces) {
        for (final address in interface.addresses) {
          if (!address.isLoopback &&
              address.address.startsWith(
                RegExp(r'10\.|192\.168\.|172\.'),
              )) {
            return address.address;
          }
        }
      }

      for (final interface in interfaces) {
        if (interface.addresses.isNotEmpty) {
          return interface.addresses.first.address;
        }
      }
    } catch (_) {}

    return null;
  }

  // ------------------------------------------------------------- discovery

  /// Sweeps the local /24 subnet looking for a sender that accepts [code].
  Future<String> discover(
    String code, {
    void Function(double progress)? onProgress,
  }) async {
    final ip = await localIp();

    if (ip == null) {
      throw TransferException(
        'No Wi-Fi or hotspot connection found.',
      );
    }

    final prefix = ip.substring(
      0,
      ip.lastIndexOf('.') + 1,
    );

    final hosts = <String>[
      for (var i = 1; i < 255; i++) '$prefix$i',
    ]..remove(ip);

    var scanned = 0;
    const batchSize = 32;

    for (
      var start = 0;
      start < hosts.length;
      start += batchSize
    ) {
      final batch = hosts
          .skip(start)
          .take(batchSize)
          .toList();

      final results = await Future.wait(
        batch.map(
          (host) => _probe(host, code),
        ),
      );

      scanned += batch.length;

      if (hosts.isNotEmpty) {
        onProgress?.call(
          scanned / hosts.length,
        );
      }

      for (var i = 0; i < results.length; i++) {
        if (results[i] == _ProbeResult.ok) {
          return batch[i];
        }

        if (results[i] == _ProbeResult.wrongCode) {
          throw TransferException(
            'Invalid code. Check the 6 digits on the old phone.',
          );
        }
      }
    }

    throw TransferException(
      'Sender not found. Keep both phones on the same Wi-Fi / '
      'hotspot and try again.',
    );
  }

  Future<_ProbeResult> _probe(
    String host,
    String code,
  ) async {
    final client = HttpClient()
      ..connectionTimeout = const Duration(
        milliseconds: 700,
      );

    try {
      final request = await client
          .getUrl(
            Uri.parse(
              'http://$host:$kTransferPort/handshake?code=$code',
            ),
          )
          .timeout(
            const Duration(milliseconds: 900),
          );

      final response = await request.close().timeout(
            const Duration(milliseconds: 900),
          );

      if (response.statusCode == 200) {
        final body = await utf8.decoder.bind(response).join();
        try {
          final data = jsonDecode(body) as Map<String, dynamic>;
          final token = data['token'];
          if (token is String && token.isNotEmpty) {
            _sessionToken = token;
            return _ProbeResult.ok;
          }
        } catch (_) {}
        return _ProbeResult.miss;
      }

      await response.drain<void>();

      if (response.statusCode == 401) {
        return _ProbeResult.wrongCode;
      }

      return _ProbeResult.miss;
    } catch (_) {
      return _ProbeResult.miss;
    } finally {
      client.close(force: true);
    }
  }

  // --------------------------------------------------------------- download

  /// Downloads the payload from [host] with live progress.
  Future<Uint8List> download(
    String host,
    String code, {
    void Function(double progress)? onProgress,
  }) async {
    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 8);

    try {
      final token = _sessionToken;
      if (token == null || token.isEmpty) {
        throw TransferException('Transfer session expired. Start again.');
      }

      final request = await client.getUrl(
        Uri.parse(
          'http://$host:$kTransferPort/payload?code=$code&token=${Uri.encodeQueryComponent(token)}',
        ),
      );

      final response = await request.close();

      if (response.statusCode == 401) {
        throw TransferException('Invalid code.');
      }

      if (response.statusCode != 200) {
        throw TransferException(
          'Transfer interrupted (${response.statusCode}).',
        );
      }

      final total = response.contentLength;
      if (total > kMaxTransferBytes) {
        throw TransferException('Transfer is too large to safely receive.');
      }
      final bytes = <int>[];

      await for (final chunk in response) {
        if (bytes.length + chunk.length > kMaxTransferBytes) {
          throw TransferException('Transfer exceeded the safety limit.');
        }
        bytes.addAll(chunk);

        if (total > 0) {
          onProgress?.call(
            bytes.length / total,
          );
        }
      }

      if (total > 0 && bytes.length < total) {
        throw TransferException(
          'Transfer interrupted.',
        );
      }

      return Uint8List.fromList(bytes);
    } on TransferException {
      rethrow;
    } catch (_) {
      throw TransferException(
        'Transfer interrupted. Try again.',
      );
    } finally {
      client.close(force: true);
    }
  }

  // --------------------------------------------------------------- payload

  /// Zips every record, setting and vault file into a single archive.
  Future<Uint8List> buildPayload() async {
    final storage = StorageService.instance;
    final archive = Archive();

    final manifest = <String, dynamic>{
      'version': 1,
      'createdAt': DateTime.now().toIso8601String(),
      'profiles': storage.profiles.values
          .map(_profileJson)
          .toList(),
      'categories': storage.categories.values
          .map(_categoryJson)
          .toList(),
      'documents': storage.documents.values
          .map(_docJson)
          .toList(),
      'settings': <String, dynamic>{
        for (final key in _portableSettingKeys)
          if (storage.settings.get(key) != null)
            key: storage.settings.get(key),
      },
    };

    for (final doc in storage.documents.values) {
      for (final filePath in doc.filePaths) {
        final file = File(filePath);

        if (!file.existsSync()) {
          continue;
        }

        final fileBytes = file.readAsBytesSync();

        archive.addFile(
          ArchiveFile(
            'vault/${doc.id}/${p.basename(filePath)}',
            fileBytes.length,
            fileBytes,
          ),
        );
      }
    }

    final manifestBytes = utf8.encode(
      jsonEncode(manifest),
    );

    archive.addFile(
      ArchiveFile(
        'manifest.json',
        manifestBytes.length,
        manifestBytes,
      ),
    );

    final List<int>? zipped = ZipEncoder().encode(archive);

    // archive package versions may return a nullable List<int>.
    return Uint8List.fromList(
      zipped ?? const <int>[],
    );
  }

  // --------------------------------------------------------------- restore

  /// Replaces all local data with the received payload.
  Future<void> restorePayload(
    Uint8List bytes,
  ) async {
    final Archive archive;

    try {
      archive = ZipDecoder().decodeBytes(bytes);
    } catch (_) {
      throw TransferException(
        'The received data is corrupted.',
      );
    }

    final manifestFile = archive.files.firstWhere(
      (file) => file.name == 'manifest.json',
      orElse: () => throw TransferException(
        'The received data is incomplete.',
      ),
    );

    final manifestContent = manifestFile.content;

    if (manifestContent == null) {
      throw TransferException(
        'The received manifest is empty.',
      );
    }

    final manifest = jsonDecode(
      utf8.decode(
        List<int>.from(manifestContent),
      ),
    ) as Map<String, dynamic>;

    if (bytes.length > kMaxTransferBytes) {
      throw TransferException('Transfer exceeded the safety limit.');
    }

    final documents = manifest['documents'];
    if (documents is! List) {
      throw TransferException('The received manifest is invalid.');
    }

    bool safePart(String value) =>
        value.isNotEmpty &&
        value != '.' &&
        value != '..' &&
        !value.contains('/') &&
        !value.contains('\\') &&
        !value.contains('..');

    for (final raw in documents) {
      if (raw is! Map) throw TransferException('The received manifest is invalid.');
      final id = raw['id'];
      if (id is! String || !safePart(id)) {
        throw TransferException('The received manifest contains an unsafe document id.');
      }
    }

    for (final file in archive.files) {
      if (!file.isFile) continue;
      final normalized = file.name.replaceAll('\\', '/');
      if (normalized == 'manifest.json' || !normalized.startsWith('vault/')) {
        if (normalized != 'manifest.json') {
          throw TransferException('The received archive contains an unsafe path.');
        }
        continue;
      }
      final parts = normalized.split('/');
      if (parts.length != 3 || !safePart(parts[1]) || !safePart(parts[2])) {
        throw TransferException('The received archive contains an unsafe path.');
      }
    }

    final storage = StorageService.instance;

    await storage.replaceAll(
      writeFile: (
        docId,
        name,
        data,
      ) async {
        final dir = Directory(
          p.join(
            storage.vaultDir.path,
            docId,
          ),
        );

        if (!dir.existsSync()) {
          dir.createSync(
            recursive: true,
          );
        }

        final target = File(
          p.join(
            dir.path,
            name,
          ),
        );

        await target.writeAsBytes(data);

        return target.path;
      },
      files: [
        for (final file in archive.files)
          if (file.isFile &&
              file.name.startsWith('vault/') &&
              file.name.split('/').length >= 3)
            (
              docId: file.name.split('/')[1],
              name: p.basename(file.name),
              data: List<int>.from(
                file.content ?? const <int>[],
              ),
            ),
      ],
      manifest: manifest,
    );
  }

  // -------------------------------------------------------------- settings

  static const _portableSettingKeys = [
    SettingsKeys.themeMode,
    SettingsKeys.biometricEnabled,
    SettingsKeys.maskByDefault,
    SettingsKeys.reminderDaysBefore,
    SettingsKeys.onboarded,
    SettingsKeys.activeProfile,
    SettingsKeys.lockOnBackground,
    SettingsKeys.appLockEnabled,
  ];

  // ----------------------------------------------------------- serializers

  static Map<String, dynamic> _profileJson(
    Profile profile,
  ) =>
      {
        'id': profile.id,
        'name': profile.name,
        'relation': profile.relation,
        'color': profile.colorValue,
        'icon': profile.iconCodePoint,
        'isDefault': profile.isDefault,
        'createdAt':
            profile.createdAt.millisecondsSinceEpoch,
      };

  static Map<String, dynamic> _categoryJson(
    DocCategory category,
  ) =>
      {
        'id': category.id,
        'name': category.name,
        'icon': category.iconCodePoint,
        'color': category.colorValue,
        'mask': category.maskSensitive,
        'builtIn': category.isBuiltIn,
      };

  static Map<String, dynamic> _docJson(
    DocItem document,
  ) =>
      {
        'id': document.id,
        'title': document.title,
        'categoryId': document.categoryId,
        'documentNumber': document.documentNumber,
        'profileId': document.profileId,
        'issueDate':
            document.issueDate?.millisecondsSinceEpoch,
        'expiryDate':
            document.expiryDate?.millisecondsSinceEpoch,
        'notes': document.notes,
        'fileNames':
            document.filePaths.map(p.basename).toList(),
        'fileType': document.fileType.index,
        'maskByDefault': document.maskByDefault,
        'favorite': document.favorite,
        'createdAt':
            document.createdAt.millisecondsSinceEpoch,
        'updatedAt':
            document.updatedAt.millisecondsSinceEpoch,
      };
}

enum _ProbeResult {
  ok,
  wrongCode,
  miss,
}

typedef VoidCallback = void Function();
