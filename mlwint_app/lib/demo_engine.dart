// MLWINT Flutter window: the demo engine. Save as MLWINT/mlwint_app/lib/demo_engine.dart
// Answers the same commands as the Python engine (scripts/mlwint_engine.py) from built-in sample data
// (assets/demo/demo.json, made by packaging/make_demo_data.py), and plays a scan as a timed sequence of events.
// Used by the web demo, and on Windows with --dart-define=MLWINT_DEMO=true. Nothing is read, scanned or uploaded.
import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;

import 'package:flutter/services.dart' show rootBundle;

import 'engine_api.dart';

const _rank = {'LOW': 0, 'GUARDED': 1, 'ELEVATED': 2, 'HIGH': 3, 'SEVERE': 4};
const _wholePc = 'analysis-20261112-091200.json';

class DemoEngine extends EngineApi {
  static List<String> samplePaths({bool folder = false}) =>
      [folder ? r'C:\Users\demo\Downloads' : r'C:\Users\demo\Downloads\setup.exe'];

  final _events = StreamController<Json>.broadcast();
  final _log = StreamController<String>.broadcast();
  late Json _data;
  final List<Json> _history = [];
  final Map<String, List<Json>> _reports = {};
  Json _settings = {'memory_days': 30, 'remember_options': true, 'animations': true, 'models_dir': '',
      'models_state': 'default models'};
  Json _options = {};
  int _memory = 138;
  bool _running = false, _scanning = false, _stop = false;

  @override
  String get root => '';
  @override
  String get python => '';
  @override
  bool get running => _running;
  @override
  bool get demo => true;
  @override
  Stream<Json> get events => _events.stream;
  @override
  Stream<String> get log => _log.stream;

  @override
  Future<Json> start() async {
    _data = jsonDecode(await rootBundle.loadString('assets/demo/demo.json')) as Json;
    for (final e in _data['history'] as List) {
      _history.add((e as Map).cast<String, dynamic>());
    }
    (_data['reports'] as Map).forEach((k, v) => _reports['$k'] = _list(v));
    _reports[_wholePc] = _wholePcResults();
    _options = {'scope': 'files', 'include_windows': false, 'paths': [r'C:\Users\demo\Downloads'],
        'types': ['dotnet', 'pdf', 'win32', 'win64'], 'recursive': true, 'deep_all': false, 'large': false,
        'reputation': 'off', 'evidence': 'needed', 'deep': 'needed', 'context': 'needed', 'max_files': 2000};
    _running = true;
    _log.add('MLWINT live demo: sample data only. Nothing on this computer is read, scanned or uploaded.');
    return {'event': 'ready', 'version': 1};
  }

  static List<Json> _list(dynamic v) => [for (final e in (v as List)) (e as Map).cast<String, dynamic>()];
  static Json _copy(Json r) => (jsonDecode(jsonEncode(r)) as Map).cast<String, dynamic>();

  /// A whole-PC scan of 1,320 files (mostly harmless system and program files), to show long lists scrolling.
  List<Json> _wholePcResults() {
    final rnd = math.Random(42);
    const folders = [r'C:\Program Files\Common Files\Example', r'C:\Program Files\Example Office\root',
        r'C:\Program Files (x86)\Example Browser\Application', r'C:\Users\demo\AppData\Local\Programs\Example Chat',
        r'C:\Program Files\Example Graphics\bin', r'D:\Games\Example Engine\Binaries'];
    const stems = ['module', 'helper', 'service', 'updater', 'runtime', 'plugin', 'codec', 'render', 'sync', 'agent'];
    final out = <Json>[];
    for (var i = 0; i < 1320; i++) {
      final dll = rnd.nextDouble() < 0.7;
      final pdf = !dll && rnd.nextDouble() < 0.15;
      final name = pdf ? 'manual_${i.toString().padLeft(4, '0')}.pdf'
          : '${stems[rnd.nextInt(stems.length)]}_${i.toString().padLeft(4, '0')}.${dll ? 'dll' : 'exe'}';
      final fmt = pdf ? 'PDF' : (rnd.nextBool() ? 'Win64' : (rnd.nextDouble() < 0.2 ? '.NET' : 'Win32'));
      var score = rnd.nextInt(13);
      var level = 'LOW';
      if (i % 165 == 7) {
        score = 21 + rnd.nextInt(17);
        level = 'GUARDED';
      }
      if (i == 611) {
        score = 44;
        level = 'ELEVATED';
      }
      out.add({
        'status': 'assessed', 'path': '${folders[i % folders.length]}\\$name', 'format': fmt, 'score': score,
        'level': level, 'verdict': level == 'LOW' ? 'CLEAN' : 'SUSPICIOUS', 'probability': score / 100,
        'summary': level == 'LOW' ? 'no meaningful sign of malware' : 'weak warning signs',
        'advice': {'headline': level == 'LOW' ? 'No action needed' : 'Fine if you expected it', 'actions': [], 'notes': []},
        'parts': [{'part': 'detector', 'points': score.toDouble(), 'reason': '$fmt detector, malware probability ${(score / 100).toStringAsFixed(3)}'}],
        'signature': {'status': 'Valid', 'signer': 'CN=Example Software Ltd'}, 'seconds': 0.4,
        'remembered': i % 3 == 0 ? {'day': '5 Nov 2026'} : null,
      });
    }
    return out;
  }

  @override
  Future<T> call<T>(String cmd, [Json args = const {}]) async {
    await Future<void>.delayed(const Duration(milliseconds: 60)); // feels like a real answer
    final dynamic out = switch (cmd) {
      'hello' => {
          'version': 1, 'versions': _data['versions'], 'root': '', 'downloads': r'C:\Users\demo\Downloads',
          'kinds': ['win32', 'win64', 'dotnet', 'pdf'],
          'choices': {'evidence': ['needed', 'all', 'none'], 'deep': ['needed', 'all', 'none'],
              'context': ['needed', 'all', 'none'], 'reputation': ['off', 'flagged', 'all']},
          'settings': _settings, 'scan_options': _options, 'memory': _memory, 'keys': _keys(),
          'privacy': _data['privacy'], 'memory_days_range': [1, 365], 'large_mb': 256,
        },
      'health' => _data['health'],
      'status' => {'memory': _memory, 'keys': _keys(), 'settings': _settings, 'scanning': _scanning},
      'history' => _history,
      'report' => _report('${args['file']}'),
      'text' => _text((args['result'] as Map).cast<String, dynamic>()),
      'set' => _set('${args['name']}', args['value']),
      'keep_options' => _keep(args),
      'reset_options' => _options,
      'forget' => _memory = 0,
      'scan' => _startScan(args),
      'stop' => _stop = true,
      'quit' => true,
      'open_report' => _openReport(args),
      'open_reports_folder' || 'reveal' => throw EngineError('Not in the live demo: the Windows app opens this in Explorer.'),
      'keys_save' || 'keys_remove' || 'keys_test' =>
        throw EngineError('Hash lookup keys work in the Windows app (the demo never contacts any service).'),
      _ => throw EngineError('unknown command $cmd'),
    };
    return out as T;
  }

  List<Json> _keys() => [
        {'name': 'malwarebazaar', 'label': 'MalwareBazaar key', 'help': 'Free: sign in at auth.abuse.ch and copy your Auth-Key', 'state': 'not set', 'saved': false, 'env': ''},
        {'name': 'virustotal', 'label': 'VirusTotal key (optional)', 'help': 'Free account at virustotal.com > your profile > API key', 'state': 'not set', 'saved': false, 'env': ''},
      ];

  Json _set(String name, dynamic value) {
    _settings = {..._settings, name: value};
    return _settings;
  }

  bool _keep(Json args) {
    final o = args['options'];
    if (o is Map) _options = o.cast<String, dynamic>();
    return true;
  }

  String _openReport(Json args) {
    if (args['kind'] == 'pdf') {
      _events.add({'event': 'open_url', 'url': 'sample-report.pdf'});
      return 'sample-report.pdf';
    }
    throw EngineError('The technical report opens in the Windows app; the demo shows the easy-to-read PDF.');
  }

  /// One earlier scan, each file compared with the previous scan of the same place (like the Python engine).
  Json _report(String file) {
    final i = _history.indexWhere((e) => e['file'] == file);
    if (i < 0) throw EngineError('that report is no longer there');
    final entry = _history[i];
    final results = [for (final r in _reports[file] ?? const <Json>[]) _copy(r)];
    Json? prev;
    for (final e in _history.skip(i + 1)) {
      if (e['whole_pc'] == entry['whole_pc'] && '${e['paths']}' == '${entry['paths']}') {
        prev = e;
        break;
      }
    }
    int? gone;
    if (prev != null && _reports[prev['file']] != null) {
      final before = {for (final r in _reports[prev['file']]!) '${r['path']}'.toLowerCase(): r};
      for (final r in results) {
        final old = before.remove('${r['path']}'.toLowerCase());
        if (old == null) {
          r['change'] = 'new';
        } else if (r['status'] == 'assessed' && old['status'] == 'assessed' && old['level'] != r['level']) {
          final worse = (_rank[r['level']] ?? 0) > (_rank[old['level']] ?? 0);
          r['change'] = '${worse ? 'worse' : 'better'} (was ${old['score']} ${old['level']})';
        } else {
          r['change'] = '';
        }
      }
      gone = before.length;
    }
    return {'entry': entry, 'results': results, 'previous': prev, 'gone': gone, 'has_pdf': true, 'has_txt': false,
        'not_checked': {}};
  }

  String _text(Json r) {
    final b = StringBuffer()
      ..writeln('${r['path']}')
      ..writeln(r['status'] == 'assessed' ? '  ${r['score']}/100 ${r['level']}  (${r['format']}, detector ${r['verdict']})' : '  not analysed: ${r['reason']}');
    for (final p in (r['parts'] as List? ?? const [])) {
      b.writeln('    ${(p['points'] as num) >= 0 ? '+' : ''}${p['points']}  ${p['part']}: ${p['reason']}');
    }
    final adv = (r['advice'] as Map?) ?? const {};
    if (adv['headline'] != null) b.writeln('  advice: ${adv['headline']}');
    for (final a in (adv['actions'] as List? ?? const [])) {
      b.writeln('    [${a['priority']}] ${a['action']}');
    }
    b.writeln('\n(sample data from the MLWINT live demo)');
    return b.toString();
  }

  // -------------------------------------------------- the scan, played as events
  bool _startScan(Json args) {
    if (_scanning) throw EngineError('a scan is already running');
    final o = (args['options'] as Map?)?.cast<String, dynamic>() ?? _options;
    final types = {for (final t in (o['types'] as List? ?? const [])) '$t'};
    if (types.isEmpty) throw EngineError('tick at least one kind of file to check');
    _scanning = true;
    _stop = false;
    unawaited(_play(o, types, args['fresh'] == true));
    return true;
  }

  Future<void> _play(Json o, Set<String> types, bool fresh) async {
    Future<void> wait(int ms) => Future<void>.delayed(Duration(milliseconds: ms));
    void ev(String name, Json data) => _events.add({'event': name, ...data});
    const fmtKind = {'Win32': 'win32', 'Win64': 'win64', '.NET': 'dotnet', 'PDF': 'pdf'};
    final whole = o['scope'] == 'pc';
    var files = [for (final r in _list(_data['scan'])) if (r['status'] != 'assessed' || types.contains(fmtKind[r['format']])) r];
    if (whole) files = [...files, ..._reports[_wholePc]!.take(40).map(_copy)];
    ev('log', {'text': 'MLWINT analyse (live demo: sample files, nothing is read or scanned)'});
    ev('phase', {'text': 'Looking for Windows programs and PDFs'});
    for (var seen = 0; seen <= 120; seen += 24) {
      ev('searching', {'seen': seen * (whole ? 40 : 1), 'found': math.min(files.length, seen ~/ 10)});
      await wait(120);
    }
    ev('counted', {'n': files.length, 'cut': false, 'note': '', 'max_files': o['max_files'] ?? 2000});
    ev('phase', {'text': 'Loading models'});
    await wait(700);
    ev('phase', {'text': 'Checking files'});
    final done = <Json>[];
    for (final (i, r) in files.indexed) {
      if (_stop) {
        ev('log', {'text': 'Stopped by you after ${done.length} of ${files.length} files'});
        break;
      }
      ev('checking', {'i': i + 1, 'n': files.length, 'path': r['path']});
      final slow = r['status'] == 'assessed' && (_rank[r['level']] ?? 0) >= 2;
      final remembered = !fresh && r['remembered'] != null;
      await wait(remembered ? 120 : (slow ? 1300 : 450));
      final out = _copy(r);
      if (fresh) out.remove('remembered');
      done.add(out);
      ev('file', {'i': i + 1, 'n': files.length, 'result': out});
    }
    await wait(500);
    final now = DateTime.now();
    String two(int v) => v.toString().padLeft(2, '0');
    final stamp = '${now.year}${two(now.month)}${two(now.day)}-${two(now.hour)}${two(now.minute)}${two(now.second)}';
    final file = 'analysis-$stamp.json';
    final levels = <String, int>{};
    for (final r in done) {
      if (r['status'] == 'assessed') levels['${r['level']}'] = (levels['${r['level']}'] ?? 0) + 1;
    }
    final where = whole ? 'Whole PC' : (o['paths'] as List? ?? const []).join(', ');
    _reports[file] = done;
    _history.insert(0, {
      'file': file, 'started': '${now.year}-${two(now.month)}-${two(now.day)} ${two(now.hour)}:${two(now.minute)}:${two(now.second)}',
      'where': where, 'paths': [for (final p in (o['paths'] as List? ?? const [])) '$p'.toLowerCase()],
      'whole_pc': whole, 'files': done.length, 'levels': levels,
      'not_checked': done.where((r) => r['status'] != 'assessed').length, 'memory': '', 'seconds': done.length * 2,
    });
    _memory += done.length;
    _scanning = false;
    final summary = ['SEVERE', 'HIGH', 'ELEVATED', 'GUARDED', 'LOW']
        .where((l) => (levels[l] ?? 0) > 0)
        .map((l) => '${levels[l]} $l')
        .join(', ');
    ev('finished', {
      'file': file, 'stopped': _stop, 'count': done.length, 'skipped': '', 'pdf': 'sample-report.pdf',
      'memory': fresh ? '' : 'Memory: 2 unchanged (earlier result used)', 'memory_count': _memory,
      'head': ['MLWINT analysis (live demo)', 'Analysed ${done.length} files: $summary'],
    });
  }

  @override
  Future<void> quit() async {
    _stop = true;
    _running = false;
  }
}
