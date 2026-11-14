// MLWINT Flutter window: talks to the Python engine (scripts/mlwint_engine.py).
// Save as MLWINT/mlwint_app/lib/engine.dart
// The engine runs in the EMBER2024 environment as a child process; messages are JSON lines on stdin / stdout.
// No network port is opened. Read-only like the rest of MLWINT.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'engine_api.dart';

export 'engine_api.dart';

class Engine extends EngineApi {
  Process? _process;
  int _nextId = 1;
  final _pending = <int, Completer<dynamic>>{};
  final _events = StreamController<Json>.broadcast();
  final _log = StreamController<String>.broadcast();
  @override
  String root = '';
  @override
  String python = '';
  @override
  bool get running => _process != null;

  /// Events from the engine: ready, log, phase, searching, counted, checking, file, finished, failed, exited.
  @override
  Stream<Json> get events => _events.stream;

  /// Lines the engine (or MLWINT's tools) printed: shown in the Scan page's log.
  @override
  Stream<String> get log => _log.stream;

  /// MLWINT folder: MLWINT_ROOT, else the first folder above this app (or the current folder) that holds the engine.
  static String? findRoot() {
    final env = Platform.environment['MLWINT_ROOT'];
    if (env != null && File('$env/scripts/mlwint_engine.py').existsSync()) return env;
    for (final start in [File(Platform.resolvedExecutable).parent, Directory.current]) {
      Directory? d = start;
      for (var i = 0; i < 10 && d != null; i++) {
        if (File('${d.path}/scripts/mlwint_engine.py').existsSync()) return d.path;
        final up = d.parent;
        d = up.path == d.path ? null : up;
      }
    }
    return null;
  }

  /// The EMBER2024 environment's pythonw.exe (no console window), or MLWINT_PYTHON.
  static String? findPython(String root) {
    final env = Platform.environment['MLWINT_PYTHON'];
    if (env != null && File(env).existsSync()) return env;
    for (final name in ['pythonw.exe', 'python.exe']) {
      final p = '$root\\experiments\\ember2024\\.venv\\Scripts\\$name';
      if (File(p).existsSync()) return p;
    }
    return null;
  }

  @override
  Future<Json> start() async {
    final r = findRoot();
    if (r == null) {
      throw EngineError('Could not find the MLWINT folder (scripts/mlwint_engine.py). '
          'Run the app from inside the MLWINT folder, or set MLWINT_ROOT.');
    }
    final py = findPython(r);
    if (py == null) {
      throw EngineError('Could not find experiments\\ember2024\\.venv\\Scripts\\pythonw.exe in $r. '
          'Set MLWINT_PYTHON to the Python of the EMBER2024 environment.');
    }
    root = r;
    python = py;
    final ready = Completer<Json>();
    final p = await Process.start(py, ['-u', '$r\\scripts\\mlwint_engine.py'],
        workingDirectory: r, environment: {'PYTHONIOENCODING': 'utf-8', 'PYTHONUTF8': '1'});
    _process = p;
    p.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
      Json msg;
      try {
        msg = jsonDecode(line) as Json;
      } catch (_) {
        _log.add(line);
        return;
      }
      if (msg.containsKey('id')) {
        final c = _pending.remove(msg['id']);
        if (c == null) return;
        if (msg['ok'] == true) {
          c.complete(msg['data']);
        } else {
          c.completeError(EngineError('${msg['error']}'));
        }
      } else if (msg['event'] == 'ready' && !ready.isCompleted) {
        ready.complete(msg);
      } else {
        if (msg['event'] == 'log') _log.add('${msg['text']}');
        _events.add(msg);
      }
    });
    p.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen(_log.add);
    unawaited(p.exitCode.then((code) {
      _process = null;
      for (final c in _pending.values) {
        c.completeError(EngineError('The MLWINT engine stopped (exit code $code).'));
      }
      _pending.clear();
      if (!ready.isCompleted) ready.completeError(EngineError('The MLWINT engine stopped at once (exit code $code). See the log.'));
      _events.add({'event': 'exited', 'code': code});
    }));
    return ready.future.timeout(const Duration(seconds: 60),
        onTimeout: () => throw EngineError('The MLWINT engine did not start within 60 seconds.'));
  }

  /// Sends one command; completes with the engine's answer (or an EngineError with its reason).
  @override
  Future<T> call<T>(String cmd, [Json args = const {}]) {
    final p = _process;
    if (p == null) return Future.error(EngineError('The MLWINT engine is not running.'));
    final id = _nextId++;
    final c = Completer<dynamic>();
    _pending[id] = c;
    p.stdin.writeln(jsonEncode({'id': id, 'cmd': cmd, ...args}));
    return c.future.then((v) => v as T);
  }

  @override
  Future<void> quit() async {
    final p = _process;
    if (p == null) return;
    try {
      p.stdin.writeln(jsonEncode({'id': 0, 'cmd': 'quit'}));
      await p.stdin.close();
      await p.exitCode.timeout(const Duration(seconds: 8));
    } catch (_) {
      p.kill();
    }
  }
}