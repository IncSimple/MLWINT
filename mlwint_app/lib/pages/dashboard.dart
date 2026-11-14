// MLWINT Flutter window: Dashboard (home). Save as MLWINT/mlwint_app/lib/pages/dashboard.dart
//   hero: protection status as a two-tone headline that rises in word by word, quick actions, and the threat orb
//         with the highest score of the last scan, over moving light streaks
//   the last scan in numbers [ 01 ]..[ 05 ] (count up), recent findings, and MLWINT's parts
import 'package:material_ui/material_ui.dart';

import '../orb.dart';
import '../smooth.dart';
import '../state.dart';
import '../theme.dart';

class DashboardPage extends StatefulWidget {
  const DashboardPage({super.key});
  @override
  State<DashboardPage> createState() => _DashboardPageState();
}

class _DashboardPageState extends State<DashboardPage> {
  String? _file;
  Future<Json>? _report;

  Future<Json>? reportOf(AppState app, Json? latest) {
    final f = latest?['file'] as String?;
    if (f != _file) {
      _file = f;
      _report = f == null ? null : app.engine.call<Json>('report', {'file': f});
    }
    return _report;
  }

  static int? daysAgo(String? started) {
    final d = DateTime.tryParse('$started');
    return d == null ? null : DateTime.now().difference(d).inDays;
  }

  /// (first part, second part, sentence, glow) for the hero.
  (String, String, String, Color) status(Json? e, ColorScheme s) {
    if (e == null) {
      return ('Welcome to', 'MLWINT · run your first check',
          'A quick scan of your Downloads folder takes a few minutes. Nothing is ever deleted, moved, run or uploaded.',
          s.primary);
    }
    final lv = (e['levels'] as Map?)?.cast<String, dynamic>() ?? {};
    int n(String l) => (lv[l] as int?) ?? 0;
    final act = n('SEVERE') + n('HIGH'), careful = n('ELEVATED');
    final when = 'Last scan ${e['started']} · ${e['where']}.';
    final age = daysAgo(e['started'] as String?);
    final old = age != null && age >= 7 ? ' It is $age days old: scan again to stay up to date.' : '';
    if (act > 0) {
      return ('$act file${act > 1 ? 's need' : ' needs'}', 'your attention now',
          'Very likely harmful. Open the findings below and follow the steps. $when$old', colourOf('SEVERE'));
    }
    if (careful > 0) {
      return ('$careful file${careful > 1 ? 's' : ''} to', 'handle with care',
          'Clear warning signs: do not open ${careful > 1 ? 'them' : 'it'} until you know the source. $when$old',
          colourOf('ELEVATED'));
    }
    return ('Your PC looks', 'safe and quiet', 'Your last scan found no file that needs action. $when$old', s.primary);
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = Theme.of(context).colorScheme;
    final latest = app.latest;
    final (first, second, text, glow) = status(latest, s);
    final future = reportOf(app, latest);
    return FutureBuilder<Json>(
      future: future,
      builder: (context, snap) {
        final results = [
          for (final r in ((snap.data?['results'] as List?) ?? const [])) (r as Map).cast<String, dynamic>()
        ];
        Json? worst;
        for (final r in results) {
          if (r.assessed && (worst == null || r.score > worst.score)) worst = r;
        }
        final flagged = results.where((r) => r.flagged).toList()..sort(worstFirst);
        return SmoothScroll(builder: (context, controller) => ListView(
          controller: controller,
          padding: const EdgeInsets.fromLTRB(36, 28, 36, 36),
          children: [
            _Hero(
              first: first,
              second: second,
              text: text,
              glow: glow,
              worst: worst,
              animate: app.animations,
            ),
            const SizedBox(height: 28),
            Reveal(child: _Numbers(latest: latest, animate: app.animations)),
            const SizedBox(height: 28),
            Reveal(delay: const Duration(milliseconds: 80), child: LayoutBuilder(builder: (context, box) {
              final findings = _Findings(latest: latest, flagged: flagged, loading: snap.connectionState == ConnectionState.waiting);
              const parts = _Parts();
              if (box.maxWidth < 1000) {
                return Column(children: [findings, const SizedBox(height: 22), parts]);
              }
              return Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Expanded(flex: 3, child: findings),
                const SizedBox(width: 22),
                const Expanded(flex: 2, child: parts),
              ]);
            })),
          ],
        ));
      },
    );
  }
}

class _Hero extends StatelessWidget {
  final String first, second, text;
  final Color glow;
  final Json? worst;
  final bool animate;
  const _Hero({required this.first, required this.second, required this.text, required this.glow,
      required this.worst, required this.animate});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.read(context);
    final s = Theme.of(context).colorScheme;
    return StreakField(
      glow: glow,
      animate: animate,
      child: SizedBox(
        height: 430,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(48, 40, 32, 36),
          child: Row(children: [
            Expanded(
              flex: 3,
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                const Tag('Protection status'),
                const SizedBox(height: 18),
                Headline(first, second, size: 46, animate: animate),
                const SizedBox(height: 18),
                ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 600),
                  child: Text(text, style: TextStyle(color: s.onSurfaceVariant, fontSize: 15, height: 1.5)),
                ),
                const Spacer(),
                Wrap(spacing: 12, runSpacing: 12, children: [
                  FilledButton.icon(
                    onPressed: app.scanning ? null : () => quickScan(context),
                    icon: const Icon(Icons.bolt),
                    label: const Text('Quick scan: Downloads'),
                  ),
                  OutlinedButton.icon(
                    onPressed: () => app.page.value = 1,
                    icon: const Icon(Icons.folder_open_outlined),
                    label: const Text('Choose files'),
                  ),
                  OutlinedButton.icon(
                    onPressed: app.scanning ? null : () => wholePcScan(context),
                    icon: const Icon(Icons.computer),
                    label: const Text('Whole PC'),
                  ),
                ]),
              ]),
            ),
            Expanded(
              flex: 2,
              child: ThreatOrb(
                score: worst?.score,
                level: worst?.level ?? '',
                animate: animate,
                caption: worst == null ? 'no scan yet' : 'highest score in your last scan',
              ),
            ),
          ]),
        ),
      ),
    );
  }
}

/// Dashboard "Quick scan": Downloads and its sub-folders, with the kinds and depth from the Scan page.
Future<void> quickScan(BuildContext context) async {
  final app = AppScope.read(context);
  app.scanOptions = {...app.scanOptions, 'scope': 'files', 'paths': [app.hello['downloads']], 'recursive': true};
  app.page.value = 1;
  try {
    await app.startScan();
  } on EngineError catch (e) {
    if (context.mounted) snack(context, '$e', error: true);
  }
}

const wholePcWarning = 'A whole-PC check looks at every file on all your fixed drives (the Windows folder is skipped '
    'unless you tick it).\n\nThe first time can take several hours. You can press Stop at any time · a report is '
    'still written · and later scans only check new or changed files.';

Future<void> wholePcScan(BuildContext context) async {
  final app = AppScope.read(context);
  if (!await confirm(context, 'Check the whole PC?', wholePcWarning, yes: 'Start', icon: Icons.computer)) return;
  app.scanOptions = {...app.scanOptions, 'scope': 'pc'};
  app.page.value = 1;
  try {
    await app.startScan();
  } on EngineError catch (e) {
    if (context.mounted) snack(context, '$e', error: true);
  }
}

class _Numbers extends StatelessWidget {
  final Json? latest;
  final bool animate;
  const _Numbers({required this.latest, required this.animate});
  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    final lv = (latest?['levels'] as Map?)?.cast<String, dynamic>() ?? {};
    final items = [
      for (final (name, ls, colour) in groups)
        (name, ls.fold<int>(0, (a, l) => a + ((lv[l] as int?) ?? 0)), colourOf(colour)),
      ('Not checked', (latest?['not_checked'] as int?) ?? 0, s.onSurfaceVariant),
    ];
    return Card(
      child: IntrinsicHeight(
        child: Row(children: [
          for (final (i, (name, n, c)) in items.indexed) ...[
            if (i > 0) const VerticalDivider(width: 1),
            Expanded(
              child: Appear(
                delay: Duration(milliseconds: 80 * i),
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(26, 22, 20, 24),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text('[ 0${i + 1} ]', style: TextStyle(color: s.onSurfaceVariant, fontSize: 11, letterSpacing: 2)),
                    const SizedBox(height: 10),
                    latest == null
                        ? Text('–', style: TextStyle(fontFamily: display, fontSize: 42, fontWeight: FontWeight.w300, color: c))
                        : CountUp(n,
                            animate: animate,
                            style: TextStyle(fontFamily: display, fontSize: 42, fontWeight: FontWeight.w300, color: c, height: 1.1)),
                    const SizedBox(height: 4),
                    Row(children: [
                      Container(width: 7, height: 7, decoration: BoxDecoration(color: c, shape: BoxShape.circle)),
                      const SizedBox(width: 8),
                      Text(name, style: TextStyle(color: s.onSurfaceVariant, fontSize: 13)),
                    ]),
                  ]),
                ),
              ),
            ),
          ],
        ]),
      ),
    );
  }
}

class _Findings extends StatelessWidget {
  final Json? latest;
  final List<Json> flagged;
  final bool loading;
  const _Findings({required this.latest, required this.flagged, required this.loading});
  @override
  Widget build(BuildContext context) {
    final app = AppScope.read(context);
    final s = Theme.of(context).colorScheme;
    Widget soft(String t) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 18),
        child: Text(t, style: TextStyle(color: s.onSurfaceVariant)));
    return Section(
      tag: 'Last scan',
      title: 'Recent findings',
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        if (latest == null)
          soft('No scan yet. Start with a quick scan of your Downloads.')
        else if (loading)
          const Padding(padding: EdgeInsets.all(20), child: LinearProgressIndicator())
        else if (flagged.isEmpty)
          soft('Nothing above "Looks fine" in the last scan.')
        else
          for (final (i, r) in flagged.take(6).indexed)
            Appear(
              delay: Duration(milliseconds: 50 * i),
              child: ListTile(
                contentPadding: const EdgeInsets.symmetric(horizontal: 8),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                leading: ScoreBadge(r, size: 40),
                title: Text(r.name, maxLines: 1, overflow: TextOverflow.ellipsis),
                subtitle: Text(r.headline, maxLines: 1, overflow: TextOverflow.ellipsis,
                    style: TextStyle(color: s.onSurfaceVariant)),
                trailing: LevelChip(r.level),
                onTap: () => app.openReport(latest!['file'] as String),
              ),
            ),
        if (flagged.length > 6) soft('… and ${flagged.length - 6} more in the whole scan.'),
        const SizedBox(height: 12),
        Wrap(spacing: 10, runSpacing: 10, children: [
          FilledButton.tonalIcon(
            onPressed: latest == null ? null : () => app.openReport(latest!['file'] as String),
            icon: const Icon(Icons.history),
            label: const Text('See the whole scan'),
          ),
          OutlinedButton.icon(
            onPressed: latest == null
                ? null
                : () async {
                    try {
                      await app.engine.call('open_report', {'file': latest!['file'], 'kind': 'pdf'});
                    } on EngineError catch (e) {
                      if (context.mounted) snack(context, '$e', error: true);
                    }
                  },
            icon: const Icon(Icons.picture_as_pdf_outlined),
            label: const Text('Open last report (PDF)'),
          ),
        ]),
      ]),
    );
  }
}

class _Parts extends StatelessWidget {
  const _Parts();
  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = Theme.of(context).colorScheme;
    final ok = {for (final h in app.health) '${h['part']}'.split(' (').first: h['ok'] == true};
    final keys = app.keys.where((k) => k['saved'] == true || '${k['env']}'.isNotEmpty).length;
    final tiles = [
      (Icons.lock_outline, 'Read-only', 'nothing is ever changed', true),
      (Icons.psychology_outlined, 'Detector', (ok['Detectors'] ?? true) ? 'ready' : 'missing', ok['Detectors'] ?? true),
      (Icons.code, 'capa', 'code check ${(ok['capa'] ?? true) ? 'ready' : 'missing'}', ok['capa'] ?? true),
      (Icons.science_outlined, 'Speakeasy', 'safe simulation ${(ok['Speakeasy'] ?? true) ? 'ready' : 'missing'}',
          ok['Speakeasy'] ?? true),
      (Icons.memory, 'Memory', '${app.memoryCount} files remembered', true),
      (Icons.travel_explore, 'Hash lookup', keys > 0 ? 'keys saved' : 'off · no keys', keys > 0),
    ];
    return Section(
      tag: 'Engines',
      title: 'Working for you',
      child: GridView.count(
        crossAxisCount: 2,
        shrinkWrap: true,
        physics: const NeverScrollableScrollPhysics(),
        mainAxisSpacing: 10,
        crossAxisSpacing: 10,
        childAspectRatio: 2.5,
        children: [
          for (final (i, (icon, title, sub, good)) in tiles.indexed)
            Appear(
              delay: Duration(milliseconds: 60 * i),
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                decoration: BoxDecoration(
                  color: s.surfaceContainer,
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: good ? s.primary.withValues(alpha: 0.18) : s.outlineVariant),
                ),
                child: Row(children: [
                  Icon(icon, color: good ? s.primary : s.onSurfaceVariant, size: 22),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(mainAxisAlignment: MainAxisAlignment.center, crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                      Text(title, style: const TextStyle(fontWeight: FontWeight.w600)),
                      Text(sub, maxLines: 1, overflow: TextOverflow.ellipsis,
                          style: TextStyle(color: s.onSurfaceVariant, fontSize: 12)),
                    ]),
                  ),
                ]),
              ),
            ),
        ],
      ),
    );
  }
}