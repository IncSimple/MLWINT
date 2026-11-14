// MLWINT Flutter window: History page. Save as MLWINT/mlwint_app/lib/pages/history.dart
//   left:  every earlier scan, newest first, with a small bar of its levels
//   right: the chosen scan's results, each compared with the previous scan of the same place
//          (new / worse / better / changed contents), plus its reports
import 'package:material_ui/material_ui.dart';

import '../results.dart';
import '../smooth.dart';
import '../state.dart';
import '../theme.dart';

class HistoryPage extends StatefulWidget {
  const HistoryPage({super.key});
  @override
  State<HistoryPage> createState() => _HistoryPageState();
}

class _HistoryPageState extends State<HistoryPage> {
  String? _file;
  Future<Json>? _report;
  bool hideEmpty = true;

  Future<Json>? load(AppState app, String? file) {
    if (file != _file) {
      _file = file;
      _report = file == null ? null : app.engine.call<Json>('report', {'file': file});
    }
    return _report;
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = Theme.of(context).colorScheme;
    final entries = app.history.where((e) => !hideEmpty || (e['files'] as int? ?? 0) > 0).toList();
    final file = app.historyFile ?? (entries.isEmpty ? null : entries.first['file'] as String);
    final future = load(app, file);
    return Padding(
      padding: const EdgeInsets.fromLTRB(28, 24, 28, 24),
      child: Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        SizedBox(
          width: 360,
          child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            const Tag('History'),
            const SizedBox(height: 8),
            Row(children: [
              Expanded(child: Text('Earlier scans', style: Theme.of(context).textTheme.headlineMedium)),
              IconButton(tooltip: 'Refresh', onPressed: app.refreshHistory, icon: const Icon(Icons.refresh)),
            ]),
            const SizedBox(height: 4),
            Row(children: [
              Text('${entries.length} scans', style: TextStyle(color: s.onSurfaceVariant)),
              const Spacer(),
              Text('Hide empty', style: TextStyle(color: s.onSurfaceVariant, fontSize: 12.5)),
              Switch(value: hideEmpty, onChanged: (v) => setState(() => hideEmpty = v)),
            ]),
            const SizedBox(height: 8),
            Expanded(
              child: entries.isEmpty
                  ? Center(child: Text('No scans yet.', style: TextStyle(color: s.onSurfaceVariant)))
                  : SmoothScroll(
                      pillInset: 0,
                      builder: (context, controller) => ListView.builder(
                        controller: controller,
                        itemCount: entries.length, // cards grow on hover, so no fixed row height
                        padding: const EdgeInsets.only(right: 16),
                        itemBuilder: (_, i) => _ScanCard(
                          e: entries[i],
                          selected: entries[i]['file'] == file,
                          onTap: () => setState(() => app.historyFile = entries[i]['file'] as String),
                        ),
                      ),
                    ),
            ),
          ]),
        ),
        const SizedBox(width: 24),
        Expanded(
          child: future == null
              ? Card(child: Center(child: Text('Choose a scan.', style: TextStyle(color: s.onSurfaceVariant))))
              : FutureBuilder<Json>(
                  future: future,
                  builder: (context, snap) {
                    if (snap.hasError) {
                      return Card(child: Center(child: Text('${snap.error}', style: TextStyle(color: s.error))));
                    }
                    if (!snap.hasData) return const Center(child: CircularProgressIndicator());
                    return _Report(key: ValueKey(file), data: snap.data!);
                  },
                ),
        ),
      ]),
    );
  }
}

/// What a scan looked at, as a short name: the folder or file name ("Downloads", "setup.exe  +2 more", "Whole PC").
String scanName(Json e) {
  if (e['whole_pc'] == true) return 'Whole PC';
  final parts = scanPaths(e);
  if (parts.isEmpty) return 'Scan';
  String base(String p) {
    var t = p.replaceAll('/', r'\');
    while (t.length > 3 && t.endsWith(r'\')) {
      t = t.substring(0, t.length - 1);
    }
    final i = t.lastIndexOf(r'\');
    return i < 0 || i == t.length - 1 ? t : t.substring(i + 1);
  }

  final first = base(parts.first);
  return parts.length == 1 ? first : '$first  +${parts.length - 1} more';
}

List<String> scanPaths(Json e) =>
    [for (final p in '${e['where'] ?? ''}'.split(', ')) if (p.trim().isNotEmpty) p.trim()];

const _months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/// "2026-11-13 11:10:26" -> "13 Nov 2026 · 11:10:26"
String niceStamp(String started) {
  final d = DateTime.tryParse(started);
  if (d == null) return started;
  String two(int v) => v.toString().padLeft(2, '0');
  return '${d.day} ${_months[d.month - 1]} ${d.year} · ${two(d.hour)}:${two(d.minute)}:${two(d.second)}';
}

/// One earlier scan: its name, the files count and a bar of its levels. Pointing at it drops down where it looked
/// and when it ran.
class _ScanCard extends StatefulWidget {
  final Json e;
  final bool selected;
  final VoidCallback onTap;
  const _ScanCard({required this.e, required this.selected, required this.onTap});
  @override
  State<_ScanCard> createState() => _ScanCardState();
}

class _ScanCardState extends State<_ScanCard> {
  bool hover = false;

  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    final e = widget.e;
    final selected = widget.selected;
    final lv = (e['levels'] as Map?)?.cast<String, dynamic>() ?? {};
    final files = (e['files'] as int?) ?? 0;
    final act = ((lv['SEVERE'] as int?) ?? 0) + ((lv['HIGH'] as int?) ?? 0);
    final paths = scanPaths(e);
    final seconds = e['seconds'];
    Widget fact(IconData icon, String text, {int lines = 1}) => Padding(
          padding: const EdgeInsets.only(top: 6),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Icon(icon, size: 15, color: s.primary.withValues(alpha: 0.8)),
            const SizedBox(width: 8),
            Expanded(
              child: Text(text, maxLines: lines, overflow: TextOverflow.ellipsis,
                  style: TextStyle(color: s.onSurfaceVariant, fontSize: 12.5, height: 1.4)),
            ),
          ]),
        );
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: MouseRegion(
        onEnter: (_) => setState(() => hover = true),
        onExit: (_) => setState(() => hover = false),
        child: AnimatedContainer(
          duration: Motion.short,
          decoration: BoxDecoration(
            color: selected || hover ? s.surfaceContainerHigh : s.surfaceContainerLow,
            borderRadius: BorderRadius.circular(18),
            border: Border.all(
                color: selected ? s.primary.withValues(alpha: 0.45) : (hover ? s.outline : s.outlineVariant)),
          ),
          child: Material(
            type: MaterialType.transparency,
            child: InkWell(
              borderRadius: BorderRadius.circular(18),
              onTap: widget.onTap,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 14, 16, 14),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    Expanded(
                      child: Text(scanName(e), maxLines: 1, overflow: TextOverflow.ellipsis,
                          style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 15)),
                    ),
                    if (act > 0)
                      const LevelChip('HIGH')
                    else
                      Text('$files files', style: TextStyle(color: s.onSurfaceVariant, fontSize: 12)),
                  ]),
                  // drops down on hover: where it looked and when it ran
                  AnimatedSize(
                    duration: Motion.medium,
                    curve: Motion.enter,
                    alignment: Alignment.topCenter,
                    child: AnimatedSwitcher(
                      duration: Motion.short,
                      child: !hover
                          ? const SizedBox(key: ValueKey('closed'), width: double.infinity)
                          : Column(
                              key: const ValueKey('open'),
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const SizedBox(height: 4),
                                fact(Icons.folder_outlined,
                                    e['whole_pc'] == true
                                        ? 'Every fixed drive'
                                        : paths.take(3).join('\n') + (paths.length > 3 ? '\n+${paths.length - 3} more' : ''),
                                    lines: 4),
                                fact(Icons.schedule_rounded, niceStamp('${e['started']}')),
                                if (seconds != null) fact(Icons.timer_outlined, 'took $seconds s'),
                              ],
                            ),
                    ),
                  ),
                  const SizedBox(height: 14),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(4),
                    child: SizedBox(
                      height: 6,
                      child: files == 0
                          ? Container(color: s.outlineVariant)
                          : Row(children: [
                              for (final l in levels.reversed)
                                if (((lv[l] as int?) ?? 0) > 0)
                                  Expanded(flex: (lv[l] as int), child: Container(color: colourOf(l))),
                              if (((e['not_checked'] as int?) ?? 0) > 0)
                                Expanded(flex: e['not_checked'] as int, child: Container(color: s.outline)),
                            ]),
                    ),
                  ),
                ]),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _Report extends StatelessWidget {
  final Json data;
  const _Report({super.key, required this.data});
  @override
  Widget build(BuildContext context) {
    final app = AppScope.read(context);
    final s = Theme.of(context).colorScheme;
    final e = (data['entry'] as Map).cast<String, dynamic>();
    final results = [for (final r in (data['results'] as List)) (r as Map).cast<String, dynamic>()];
    final prev = data['previous'] as Map?;
    final lv = (e['levels'] as Map?)?.cast<String, dynamic>() ?? {};
    int count(String c) => results.where((r) => r.change.startsWith(c)).length;
    Future<void> open(String kind) async {
      try {
        await app.engine.call('open_report', {'file': e['file'], 'kind': kind});
      } on EngineError catch (err) {
        if (context.mounted) snack(context, '$err', error: true);
      }
    }

    final seconds = e['seconds'];
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Card(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(24, 20, 24, 20),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Tag(e['whole_pc'] == true ? 'Whole PC' : 'Files and folders'),
                const SizedBox(height: 6),
                Text('${e['started']}', style: Theme.of(context).textTheme.headlineSmall),
                const SizedBox(height: 4),
                Text('${e['where']}', maxLines: 2, overflow: TextOverflow.ellipsis,
                    style: TextStyle(color: s.onSurfaceVariant)),
                const SizedBox(height: 12),
                Wrap(spacing: 8, runSpacing: 8, children: [
                  for (final (name, ls, c) in groups)
                    Chip(
                      avatar: CircleAvatar(backgroundColor: colourOf(c), radius: 4),
                      label: Text('${ls.fold<int>(0, (a, l) => a + ((lv[l] as int?) ?? 0))} $name'),
                    ),
                  Chip(label: Text('${e['not_checked']} not checked')),
                  if (seconds != null) Chip(label: Text('took ${seconds}s')),
                ]),
                if (prev != null) ...[
                  const SizedBox(height: 10),
                  Text(
                    'Since the scan of ${prev['started']}: ${count('new')} new, ${count('worse')} worse, '
                    '${count('better')} better${(data['gone'] as int? ?? 0) > 0 ? ', ${data['gone']} gone' : ''}.',
                    style: TextStyle(color: s.onSurfaceVariant, fontSize: 13),
                  ),
                ],
              ]),
            ),
            const SizedBox(width: 16),
            SizedBox(
              width: 220,
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                FilledButton.icon(
                    onPressed: () => open('pdf'),
                    icon: const Icon(Icons.picture_as_pdf_outlined),
                    label: Text(data['has_pdf'] == true ? 'Open report' : 'Make report (PDF)')),
                const SizedBox(height: 8),
                OutlinedButton.icon(
                    onPressed: data['has_txt'] == true ? () => open('txt') : null,
                    icon: const Icon(Icons.description_outlined, size: 18),
                    label: const Text('Technical report')),
                const SizedBox(height: 8),
                TextButton.icon(
                    onPressed: () => app.engine.call('open_reports_folder'),
                    icon: const Icon(Icons.folder_open_outlined, size: 18),
                    label: const Text('Reports folder')),
              ]),
            ),
          ]),
        ),
      ),
      const SizedBox(height: 20),
      Expanded(
        child: ResultsPane(
          results: results,
          version: results.length,
          compare: prev != null,
          empty: 'This scan looked at no files.',
        ),
      ),
    ]);
  }
}