// MLWINT Flutter window in the browser (the live demo). Save as MLWINT/mlwint_app/lib/platform/web.dart
import 'dart:js_interop';

import '../demo_engine.dart';
import '../engine_api.dart';

@JS('window.open')
external JSAny? _windowOpen(JSString url, JSString target);

const demoMode = true;

EngineApi createEngine() => DemoEngine();

List<String> pickPaths({bool folder = false, String title = ''}) => DemoEngine.samplePaths(folder: folder);

void openUrl(String url) {
  _windowOpen(url.toJS, '_blank'.toJS);
}

void appendErrorLog(String root, String text) {}
