// MLWINT Flutter window: everything the pages share (engine, settings, the running scan, history).
// Save as MLWINT/mlwint_app/lib/state.dart
import 'dart:async';
import 'dart:collection';

import 'package:material_ui/material_ui.dart';

import 'engine_api.dart';
import 'platform/platform.dart';

export 'engine_api.dart' show Json, EngineError;

// ---------------------------------------------------------------------------------------------- levels
const levels = ['LOW', 'GUARDED', 'ELEVATED', 'HIGH', 'SEVERE'];
const levelRank = {'LOW': 0, 'GUARDED': 1, 'ELEVATED': 2, 'HIGH': 3, 'SEVERE': 4};
const levelColour = {
  'LOW': Color(0xFF6EE07A),
  'GUARDED': Color(0xFF57B8F0),
  'ELEVATED': Color(0xFFF5BD45),
  'HIGH': Color(0xFFFF8D42),
  'SEVERE': Color(0xFFFF4F62),
};
const levelWords = {
  'LOW': 'Looks fine',
  'GUARDED': 'Worth a look',
  'ELEVATED': 'Be careful',
  'HIGH': 'Act now',
  'SEVERE': 'Act now',
};

/// The four groups shown everywhere (dashboard numbers, history list).
const groups = [
  ('Act now', ['SEVERE', 'HIGH'], 'HIGH'),
  ('Be careful', ['ELEVATED'], 'ELEVATED'),
  ('Worth a look', ['GUARDED'], 'GUARDED'),
  ('Looks fine', ['LOW'], 'LOW'),
];

Color colourOf(String? level) => levelColour[level] ?? const Color(0xFF7D8F7D);

// ---------------------------------------------------------------------------------------------- results
extension ResultX on Json {
  bool get assessed => this['status'] == 'assessed';
  int get score => (this['score'] as num?)?.round() ?? -1;
  String get level => '${this['level'] ?? ''}';
  String get path => '${this['path'] ?? ''}';
  String get name {
    final p = path.replaceAll('/', '\\');
    final i = p.lastIndexOf('\\');
    return i < 0 ? p : p.substring(i + 1);
  }

  String get folder {
    final p = path.replaceAll('/', '\\');
    final i = p.lastIndexOf('\\');
    return i < 0 ? '' : p.substring(0, i);
  }

  Json get advice => (this['advice'] as Map?)?.cast<String, dynamic>() ?? const {};
  String get headline => assessed ? '${advice['headline'] ?? this['summary'] ?? ''}' : '${this['reason'] ?? ''}';
  String get change => '${this['change'] ?? ''}';
  bool get flagged => assessed && level != 'LOW';

  String get howChecked {
    if (!assessed) return '';
    final rem = this['remembered'];
    if (rem is Map) return 'remembered (${rem['day']})';
    return this['large_file'] == true ? 'large-file check' : 'checked now';
  }
}

/// Worst first; files that could not be analysed go last.
int worstFirst(Json a, Json b) => b.score.compareTo(a.score);

// ---------------------------------------------------------------------------------------------- app state
enum ScanPhase { idle, searching, loading, checking, finishing, done, failed }

class AppState extends ChangeNotifier {
  AppState() {
    engine.log.listen(_addLog);
    engine.events.listen(_onEvent);
  }

  final EngineApi engine = createEngine(); // the Python engine on Windows, the demo engine on the web
  Json hello = {};
  String? startError;
  bool starting = true;

  // settings + status
  Json settings = {};
  Json scanOptions = {};
  int memoryCount = 0;
  List<Json> keys = [];
  List<Json> health = [];
  bool get animations => settings['animations'] != false;

  // the scan
  ScanPhase phase = ScanPhase.idle;
  String phaseText = '';
  int seen = 0, found = 0, done = 0, total = 0;
  String current = '';
  String note = '';
  bool stopping = false;
  final List<Json> results = [];
  final counts = <String, int>{};
  int failedCount = 0;
  Json? lastInfo;
  String? lastError;
  bool get scanning => const [ScanPhase.searching, ScanPhase.loading, ScanPhase.checking, ScanPhase.finishing]
      .contains(phase);

  // history
  List<Json> history = [];
  String? historyFile; // the report the History page shows

  // navigation: 0 Dashboard, 1 Scan, 2 History, 3 Settings, 4 Help
  final page = ValueNotifier(0);
  void openReport(String file) {
    historyFile = file;
    page.value = 2;
    notifyListeners();
  }

  /// Newest scan that looked at files (an empty or stopped-at-once scan says nothing).
  Json? get latest => history.where((e) => (e['files'] as int? ?? 0) > 0).firstOrNull;

  // log (last 2000 lines)
  final log = ListQueue<String>();
  final logVersion = ValueNotifier(0);

  /// Repaint after a page changed a field directly (scan options, keys).
  void changed() => notifyListeners();

  Timer? _tick;
  bool _dirty = false;
  int resultsVersion = 0;

  /// Asks for a repaint at most every 120 ms while files stream in (a whole-PC scan can send hundreds a second).
  void _soon() {
    _dirty = true;
    _tick ??= Timer(const Duration(milliseconds: 120), () {
      _tick = null;
      if (_dirty) {
        _dirty = false;
        notifyListeners();
      }
    });
  }

  Future<void> start() async {
    starting = true;
    startError = null;
    notifyListeners();
    try {
      await engine.start();
      hello = await engine.call<Json>('hello');
      settings = (hello['settings'] as Map).cast<String, dynamic>();
      scanOptions = (hello['scan_options'] as Map).cast<String, dynamic>();
      memoryCount = hello['memory'] as int? ?? 0;
      keys = _list(hello['keys']);
      await refreshHistory();
      unawaited(refreshHealth());
    } catch (e) {
      startError = '$e';
    }
    starting = false;
    notifyListeners();
  }

  Future<void> restart() async {
    await engine.quit();
    hello = {};
    await start();
  }

  static List<Json> _list(dynamic v) => [for (final e in (v as List? ?? const [])) (e as Map).cast<String, dynamic>()];

  void addLog(String line) => _addLog(line);

  void _addLog(String line) {
    log.add(line);
    while (log.length > 2000) {
      log.removeFirst();
    }
    logVersion.value++;
  }

  Future<void> refreshHistory() async {
    try {
      history = _list(await engine.call('history'));
    } catch (e) {
      _addLog('History: $e');
    }
    notifyListeners();
  }

  Future<void> refreshHealth() async {
    try {
      health = _list(await engine.call('health'));
    } catch (e) {
      _addLog('Health: $e');
    }
    notifyListeners();
  }

  Future<void> refreshStatus() async {
    try {
      final s = await engine.call<Json>('status');
      memoryCount = s['memory'] as int? ?? memoryCount;
      keys = _list(s['keys']);
      settings = (s['settings'] as Map).cast<String, dynamic>();
    } catch (_) {}
    notifyListeners();
  }

  Future<void> setSetting(String name, dynamic value) async {
    settings = await engine.call<Json>('set', {'name': name, 'value': value});
    if (name == 'models_dir') unawaited(refreshHealth());
    notifyListeners();
  }

  // -------------------------------------------------- scanning
  Future<void> startScan({bool fresh = false}) async {
    results.clear();
    counts.clear();
    failedCount = 0;
    seen = found = done = total = 0;
    current = note = '';
    lastInfo = null;
    lastError = null;
    stopping = false;
    phase = ScanPhase.searching;
    phaseText = 'Looking for Windows programs and PDFs';
    resultsVersion++;
    notifyListeners();
    try {
      await engine.call('scan', {'options': scanOptions, 'fresh': fresh});
    } catch (e) {
      phase = ScanPhase.failed;
      lastError = '$e';
      notifyListeners();
      rethrow;
    }
  }

  Future<void> stopScan() async {
    stopping = true;
    notifyListeners();
    await engine.call('stop');
  }

  Future<void> keepOptions() async {
    try {
      await engine.call('keep_options', {'options': scanOptions});
    } catch (_) {}
  }

  void _onEvent(Json e) {
    switch (e['event']) {
      case 'phase':
        phaseText = '${e['text']}';
        phase = phaseText.startsWith('Loading')
            ? ScanPhase.loading
            : phaseText.startsWith('Checking')
                ? ScanPhase.checking
                : ScanPhase.searching;
        _soon();
      case 'searching':
        seen = e['seen'] as int;
        found = e['found'] as int;
        _soon();
      case 'counted':
        total = e['n'] as int;
        note = '${e['note'] ?? ''}';
        if (e['cut'] == true) note = 'Stopped looking at the limit of ${e['max_files']} files. $note';
        _soon();
      case 'checking':
        current = '${e['path']}';
        _soon();
      case 'file':
        final r = (e['result'] as Map).cast<String, dynamic>();
        done = e['i'] as int;
        total = e['n'] as int;
        results.add(r);
        if (r.assessed) {
          counts[r.level] = (counts[r.level] ?? 0) + 1;
        } else {
          failedCount++;
        }
        if (done == total) phase = ScanPhase.finishing;
        resultsVersion++;
        _soon();
      case 'finished':
        lastInfo = e;
        phase = ScanPhase.done;
        memoryCount = e['memory_count'] as int? ?? memoryCount;
        current = '';
        resultsVersion++;
        notifyListeners();
        unawaited(refreshHistory());
      case 'failed':
        lastError = '${e['error']}';
        phase = ScanPhase.failed;
        notifyListeners();
      case 'open_url': // the demo's sample PDF report
        openUrl(Uri.base.resolve('${e['url']}').toString());
      case 'exited':
        if (!starting) {
          startError = 'The MLWINT engine stopped (exit code ${e['code']}). See the log on the Scan page.';
          if (scanning) phase = ScanPhase.failed;
          notifyListeners();
        }
    }
  }

  Json? get worst {
    Json? w;
    for (final r in results) {
      if (r.assessed && (w == null || r.score > w.score)) w = r;
    }
    return w;
  }
}

/// Gives every page the AppState: `AppScope.of(context)`.
class AppScope extends InheritedNotifier<AppState> {
  const AppScope({super.key, required AppState state, required super.child}) : super(notifier: state);

  static AppState of(BuildContext context) => context.dependOnInheritedWidgetOfExactType<AppScope>()!.notifier!;

  /// Same, without rebuilding when the state changes (for callbacks).
  static AppState read(BuildContext context) => context.getInheritedWidgetOfExactType<AppScope>()!.notifier!;
}