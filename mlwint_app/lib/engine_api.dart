// MLWINT Flutter window: what every engine offers (the real Python engine on Windows, or the demo engine on the
// web). Save as MLWINT/mlwint_app/lib/engine_api.dart
import 'dart:async';

typedef Json = Map<String, dynamic>;

class EngineError implements Exception {
  final String message;
  EngineError(this.message);
  @override
  String toString() => message;
}

abstract class EngineApi {
  /// MLWINT folder and Python in use (empty in the demo).
  String get root;
  String get python;

  /// true while the engine can answer.
  bool get running;

  /// true for the web / portfolio demo: sample data, nothing is scanned.
  bool get demo => false;

  /// Events: ready, log, phase, searching, counted, checking, file, finished, failed, exited.
  Stream<Json> get events;

  /// Lines for the Scan page's log.
  Stream<String> get log;

  Future<Json> start();

  /// Sends one command; completes with the answer (or an EngineError with its reason).
  Future<T> call<T>(String cmd, [Json args = const {}]);

  Future<void> quit();
}
