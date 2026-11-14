// MLWINT Flutter window on Windows. Save as MLWINT/mlwint_app/lib/platform/native.dart
import 'dart:io';

import '../demo_engine.dart';
import '../engine.dart';
import '../win_dialogs.dart' as win;

/// `flutter run --dart-define=MLWINT_DEMO=true` shows the sample data instead of scanning (screenshots, demos).
const demoMode = bool.fromEnvironment('MLWINT_DEMO');

EngineApi createEngine() => demoMode ? DemoEngine() : Engine();

List<String> pickPaths({bool folder = false, String title = ''}) =>
    demoMode ? DemoEngine.samplePaths(folder: folder) : win.pickPaths(folder: folder, title: title);

void openUrl(String url) {
  if (url.startsWith('https://')) Process.start('explorer.exe', [url]);
}

void appendErrorLog(String root, String text) {
  if (root.isEmpty) return;
  try {
    File('$root\\reports\\app-errors.txt').writeAsStringSync(text, mode: FileMode.append);
  } catch (_) {}
}
