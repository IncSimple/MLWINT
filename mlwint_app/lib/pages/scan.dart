// MLWINT Flutter window: Scan page. Save as MLWINT/mlwint_app/lib/pages/scan.dart
//   left:  what to check (files and folders, or the whole PC), which kinds, how deep
//   right: the live scan (orb, progress, counters) and the results list with its detail panel
import 'package:material_ui/material_ui.dart';

import '../orb.dart';
import '../results.dart';
import '../smooth.dart';
import '../state.dart';
import '../theme.dart';
import '../platform/platform.dart';
import 'dashboard.dart' show wholePcWarning;

const kindLabels = {'win32': '32-bit programs', 'win64': '64-bit programs', 'dotnet': '.NET programs', 'pdf': 'PDF documents'};
const kindTips = {
  'dotnet': 'Programs written in C# / VB.NET',
  'pdf': 'PDF checking is still being improved: ordinary PDFs with links can score Worth a look.',
};
const choiceTips = {
  'evidence': 'capa / PDF check. needed = flagged files, risky places and all PDFs (capa: about 20-40 s a program)',
  'deep': 'Speakeasy safe simulation. needed = flagged files and unsigned files in Downloads / Temp / AppData / Desktop',
  'context': 'Where it came from, run before, running now, autostart, Defender history. needed = above Looks fine',
  'reputation': 'Hash lookup with YOUR keys: sends ONLY the SHA-256. flagged = only files above Looks fine',
};
const choiceNames = {'evidence': 'Code check', 'deep': 'Safe simulation', 'context': 'PC facts', 'reputation': 'Hash lookup'};

class ScanPage extends StatelessWidget {
  const ScanPage({super.key});
  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(builder: (context, box) {
      final narrow = box.maxWidth < 1100;
      if (narrow) {
        return SmoothScroll(builder: (context, controller) => ListView(controller: controller, padding: const EdgeInsets.all(28), children: const [
          _Options(),
          SizedBox(height: 20),
          _Live(),
          SizedBox(height: 20),
          SizedBox(height: 720, child: _Results()),
        ]));
      }
      return Padding(
        padding: const EdgeInsets.fromLTRB(28, 24, 28, 24),
        child: Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          SizedBox(
              width: 412,
              child: SmoothScroll(
                  backToTop: false,
                  pillInset: 0,
                  builder: (context, controller) =>
                      ListView(controller: controller, padding: const EdgeInsets.only(right: 18), children: const [_Options()]))),
          const SizedBox(width: 24),
          const Expanded(
            child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              _Live(),
              SizedBox(height: 20),
              Expanded(child: _Results()),
            ]),
          ),
        ]),
      );
    });
  }
}

// ---------------------------------------------------------------------------------------------- options
class _Options extends StatelessWidget {
  const _Options();

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = Theme.of(context).colorScheme;
    final o = app.scanOptions;
    final busy = app.scanning;
    final whole = o['scope'] == 'pc';
    final paths = [for (final p in (o['paths'] as List? ?? const [])) '$p'];
    final types = {for (final t in (o['types'] as List? ?? const [])) '$t'};
    void set(String k, dynamic v) {
      app.scanOptions = {...app.scanOptions, k: v};
      app.changed();
      app.keepOptions();
    }

    void addPaths(List<String> add) {
      final all = [...paths];
      for (final p in add) {
        if (!all.any((x) => x.toLowerCase() == p.toLowerCase())) all.add(p);
      }
      set('paths', all);
    }

    final reputation = '${o['reputation'] ?? 'off'}';
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      const Tag('Scan'),
      const SizedBox(height: 8),
      Text('Check files', style: Theme.of(context).textTheme.headlineMedium),
      const SizedBox(height: 18),
      Section(
        title: 'What to check',
        padding: const EdgeInsets.all(20),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          SegmentedButton<String>(
            segments: const [
              ButtonSegment(value: 'files', label: Text('Files & folders'), icon: Icon(Icons.folder_outlined)),
              ButtonSegment(value: 'pc', label: Text('Whole PC'), icon: Icon(Icons.computer)),
            ],
            selected: {whole ? 'pc' : 'files'},
            onSelectionChanged: busy ? null : (v) => set('scope', v.first),
          ),
          const SizedBox(height: 14),
          AnimatedSize(
            duration: Motion.medium,
            curve: Motion.enter,
            alignment: Alignment.topCenter,
            child: whole
                ? Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                    Text('Every fixed drive. The first time can take hours; later scans only check new or changed files.',
                        style: TextStyle(color: s.onSurfaceVariant, height: 1.45)),
                    SwitchListTile(
                      contentPadding: EdgeInsets.zero,
                      title: const Text('Include the Windows folder'),
                      value: o['include_windows'] == true,
                      onChanged: busy ? null : (v) => set('include_windows', v),
                    ),
                  ])
                : Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                    if (paths.isEmpty)
                      Container(
                        padding: const EdgeInsets.all(18),
                        decoration: BoxDecoration(
                            borderRadius: BorderRadius.circular(14),
                            border: Border.all(color: s.outlineVariant),
                            color: s.surfaceContainerLowest),
                        child: Text('Add files or folders to check.', textAlign: TextAlign.center,
                            style: TextStyle(color: s.onSurfaceVariant)),
                      ),
                    for (final p in paths)
                      Padding(
                        padding: const EdgeInsets.only(bottom: 6),
                        child: InputChip(
                          avatar: const Icon(Icons.folder_outlined, size: 18),
                          label: Text(p, overflow: TextOverflow.ellipsis),
                          tooltip: p,
                          onDeleted: busy ? null : () => set('paths', [...paths]..remove(p)),
                        ),
                      ),
                    const SizedBox(height: 8),
                    Wrap(spacing: 8, runSpacing: 8, children: [
                      FilledButton.tonalIcon(
                        onPressed: busy ? null : () => addPaths(pickPaths(title: 'Files to check')),
                        icon: const Icon(Icons.note_add_outlined, size: 18),
                        label: const Text('Add files'),
                      ),
                      FilledButton.tonalIcon(
                        onPressed: busy ? null : () => addPaths(pickPaths(folder: true, title: 'Folders to check')),
                        icon: const Icon(Icons.create_new_folder_outlined, size: 18),
                        label: const Text('Add folder'),
                      ),
                      TextButton(
                        onPressed: busy ? null : () => addPaths(['${app.hello['downloads']}']),
                        child: const Text('Downloads'),
                      ),
                      if (paths.isNotEmpty)
                        TextButton(onPressed: busy ? null : () => set('paths', <String>[]), child: const Text('Clear')),
                    ]),
                    SwitchListTile(
                      contentPadding: EdgeInsets.zero,
                      title: const Text('Include sub-folders'),
                      value: o['recursive'] == true,
                      onChanged: busy ? null : (v) => set('recursive', v),
                    ),
                  ]),
          ),
        ]),
      ),
      const SizedBox(height: 16),
      Section(
        title: 'Kinds of file',
        padding: const EdgeInsets.all(20),
        trailing: TextButton(
          onPressed: busy ? null : () => set('types', types.length == 4 ? <String>[] : kindLabels.keys.toList()),
          child: Text(types.length == 4 ? 'None' : 'All'),
        ),
        child: Wrap(spacing: 8, runSpacing: 8, children: [
          for (final k in kindLabels.keys)
            Tooltip(
              message: kindTips[k] ?? '',
              child: FilterChip(
                label: Text(kindLabels[k]!),
                selected: types.contains(k),
                onSelected: busy
                    ? null
                    : (on) => set('types', (on ? ({...types, k}) : ({...types}..remove(k))).toList()..sort()),
              ),
            ),
        ]),
      ),
      const SizedBox(height: 16),
      Section(
        title: 'How deep',
        padding: const EdgeInsets.fromLTRB(20, 20, 20, 8),
        child: Column(children: [
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Deep check'),
            subtitle: const Text('Code check and safe simulation for every file (slower)'),
            value: o['deep_all'] == true,
            onChanged: busy ? null : (v) => set('deep_all', v),
          ),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Include large files'),
            subtitle: Text('Over ${app.hello['large_mb'] ?? 256} MB: signature + report-only Defender scan'),
            value: o['large'] == true,
            onChanged: busy ? null : (v) => set('large', v),
          ),
          Theme(
            data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
            child: ExpansionTile(
              tilePadding: EdgeInsets.zero,
              title: const Text('Advanced'),
              childrenPadding: const EdgeInsets.only(bottom: 12),
              children: [
                for (final k in choiceNames.keys)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 10),
                    child: Row(children: [
                      Expanded(
                        child: Tooltip(message: choiceTips[k]!, child: Text(choiceNames[k]!)),
                      ),
                      SegmentedButton<String>(
                        showSelectedIcon: false,
                        style: const ButtonStyle(visualDensity: VisualDensity.compact),
                        segments: [
                          for (final c in ((app.hello['choices'] as Map?)?[k] as List? ?? const []))
                            ButtonSegment(value: '$c', label: Text('$c')),
                        ],
                        selected: {'${o[k]}'},
                        onSelectionChanged: busy || (o['deep_all'] == true && (k == 'evidence' || k == 'deep'))
                            ? null
                            : (v) => set(k, v.first),
                      ),
                    ]),
                  ),
                Row(children: [
                  const Expanded(child: Text('Most files per scan')),
                  SizedBox(
                    width: 120,
                    child: TextFormField(
                      key: ValueKey(o['max_files']),
                      initialValue: '${o['max_files'] ?? 2000}',
                      enabled: !busy,
                      keyboardType: TextInputType.number,
                      textAlign: TextAlign.right,
                      onFieldSubmitted: (v) => set('max_files', (int.tryParse(v) ?? 2000).clamp(1, 1000000)),
                    ),
                  ),
                ]),
              ],
            ),
          ),
        ]),
      ),
      const SizedBox(height: 16),
      AnimatedContainer(
        duration: Motion.medium,
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: (reputation == 'off' ? s.primary : colourOf('ELEVATED')).withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(16),
        ),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Icon(reputation == 'off' ? Icons.shield_outlined : Icons.public,
              color: reputation == 'off' ? s.primary : colourOf('ELEVATED'), size: 20),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              reputation == 'off'
                  ? 'Hash lookup is off: nothing leaves this PC.'
                  : 'Hash lookup is on: only SHA-256 fingerprints are sent to MalwareBazaar / VirusTotal with your '
                      'own keys. No file, name or path is sent.',
              style: const TextStyle(height: 1.45, fontSize: 13),
            ),
          ),
        ]),
      ),
      const SizedBox(height: 24),
    ]);
  }
}

// ---------------------------------------------------------------------------------------------- live scan
class _Live extends StatelessWidget {
  const _Live();

  Future<void> start(BuildContext context, {bool fresh = false}) async {
    final app = AppScope.read(context);
    if (app.scanOptions['scope'] == 'pc' &&
        !await confirm(context, 'Check the whole PC?', wholePcWarning, yes: 'Start', icon: Icons.computer)) {
      return;
    }
    try {
      await app.startScan(fresh: fresh);
    } on EngineError catch (e) {
      if (context.mounted) snack(context, '$e', error: true);
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = Theme.of(context).colorScheme;
    final t = Theme.of(context).textTheme;
    final busy = app.scanning;
    final info = app.lastInfo;
    final worst = app.worst;
    String title, line;
    switch (app.phase) {
      case ScanPhase.idle:
        title = 'Ready when you are';
        line = 'Choose what to check on the left, then start. Nothing is deleted, moved, run or uploaded.';
      case ScanPhase.searching:
        title = 'Looking for files';
        line = '${app.seen} files looked at · ${app.found} to analyse';
      case ScanPhase.loading:
        title = 'Loading models';
        line = '${app.total} files to analyse${app.note.isNotEmpty ? ' · ${app.note}' : ''}';
      case ScanPhase.checking:
        title = app.stopping ? 'Stopping after this file' : 'Checking files';
        line = app.current.isEmpty ? '${app.total} files to analyse' : app.current;
      case ScanPhase.finishing:
        title = 'Writing the report';
        line = 'Making the easy-to-read PDF';
      case ScanPhase.done:
        title = info?['stopped'] == true ? 'Stopped' : 'Done';
        final head = (info?['head'] as List?) ?? const [];
        line = [if (head.length > 1) '${head[1]}', if ('${info?['memory'] ?? ''}'.isNotEmpty) '${info!['memory']}']
            .join(' · ');
      case ScanPhase.failed:
        title = 'The scan stopped with an error';
        line = app.lastError ?? '';
    }
    final progress = app.total > 0 ? app.done / app.total : null;
    return Card(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(20, 18, 24, 18),
        child: Row(children: [
          SizedBox(
            width: 168,
            height: 168,
            child: ThreatOrb(
              compact: true,
              animate: app.animations,
              scanning: busy,
              done: app.done,
              total: app.total,
              score: busy ? null : worst?.score,
              level: worst?.level ?? '',
            ),
          ),
          const SizedBox(width: 22),
          Expanded(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Tag(busy ? 'Scanning' : 'Scan status', colour: app.phase == ScanPhase.failed ? s.error : null),
              const SizedBox(height: 6),
              AnimatedSwitcher(
                duration: Motion.medium,
                child: Text(title, key: ValueKey(title), style: t.headlineSmall),
              ),
              const SizedBox(height: 6),
              Text(line, maxLines: 2, overflow: TextOverflow.ellipsis,
                  style: TextStyle(color: app.phase == ScanPhase.failed ? s.error : s.onSurfaceVariant, height: 1.4)),
              const SizedBox(height: 14),
              AnimatedOpacity(
                opacity: busy ? 1 : 0,
                duration: Motion.medium,
                child: LinearProgressIndicator(value: busy ? progress : 0, minHeight: 6, borderRadius: BorderRadius.circular(3)),
              ),
              const SizedBox(height: 14),
              Wrap(spacing: 8, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
                for (final (name, ls, colour) in groups)
                  _Count(name, ls.fold<int>(0, (a, l) => a + (app.counts[l] ?? 0)), colourOf(colour)),
                _Count('Not analysed', app.failedCount, s.onSurfaceVariant),
              ]),
            ]),
          ),
          const SizedBox(width: 16),
          SizedBox(
            width: 200,
            child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              AnimatedSwitcher(
                duration: Motion.medium,
                child: busy
                    ? FilledButton.icon(
                        key: const ValueKey('stop'),
                        style: FilledButton.styleFrom(
                            minimumSize: const Size.fromHeight(50),
                            backgroundColor: s.errorContainer,
                            foregroundColor: s.onErrorContainer),
                        onPressed: app.stopping ? null : app.stopScan,
                        icon: const Icon(Icons.stop_rounded),
                        label: const Text('Stop'),
                      )
                    : FilledButton.icon(
                        key: const ValueKey('start'),
                        style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(50)), // same size as Open report
                        onPressed: () => start(context),
                        icon: const Icon(Icons.play_arrow_rounded),
                        label: const Text('Start scan'),
                      ),
              ),
              const SizedBox(height: 8),
              OutlinedButton.icon(
                style: OutlinedButton.styleFrom(minimumSize: const Size.fromHeight(50)),
                onPressed: info?['file'] == null
                    ? null
                    : () => app.engine.call('open_report', {'file': info!['file'], 'kind': 'pdf'}).catchError((e) {
                          if (context.mounted) snack(context, '$e', error: true);
                        }),
                icon: const Icon(Icons.picture_as_pdf_outlined, size: 18),
                label: const Text('Open report'),
              ),
              const SizedBox(height: 8),
              Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                IconButton(
                  tooltip: 'Technical report (.txt)',
                  onPressed: info?['file'] == null
                      ? null
                      : () => app.engine.call('open_report', {'file': info!['file'], 'kind': 'txt'}),
                  icon: const Icon(Icons.description_outlined),
                ),
                IconButton(
                  tooltip: 'Full re-check (ignore the memory this once)',
                  onPressed: busy ? null : () => start(context, fresh: true),
                  icon: const Icon(Icons.restart_alt),
                ),
                IconButton(tooltip: 'Log', onPressed: () => showLog(context), icon: const Icon(Icons.terminal)),
              ]),
            ]),
          ),
        ]),
      ),
    );
  }
}

class _Count extends StatelessWidget {
  final String name;
  final int n;
  final Color c;
  const _Count(this.name, this.n, this.c);
  @override
  Widget build(BuildContext context) => AnimatedContainer(
        duration: Motion.short,
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
        decoration: BoxDecoration(
          color: c.withValues(alpha: n > 0 ? 0.14 : 0.05),
          borderRadius: BorderRadius.circular(20),
        ),
        child: Text('$n  $name',
            style: TextStyle(color: n > 0 ? c : Theme.of(context).colorScheme.onSurfaceVariant, fontSize: 12.5,
                fontWeight: FontWeight.w600)),
      );
}

void showLog(BuildContext context) {
  final app = AppScope.read(context);
  showDialog(
    context: context,
    builder: (c) => Dialog(
      child: SizedBox(
        width: 960,
        height: 620,
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Row(children: [
              Expanded(child: Text('Engine log', style: Theme.of(c).textTheme.titleLarge)),
              IconButton(icon: const Icon(Icons.close), onPressed: () => Navigator.pop(c)),
            ]),
            const SizedBox(height: 12),
            Expanded(
              child: Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                    color: Theme.of(c).colorScheme.surfaceContainerLowest, borderRadius: BorderRadius.circular(12)),
                child: ValueListenableBuilder(
                  valueListenable: app.logVersion,
                  builder: (_, _, _) {
                    final lines = app.log.toList();
                    return SmoothScroll(
                      backToTop: false,
                      builder: (context, controller) => ListView.builder(
                        controller: controller,
                        reverse: true,
                        itemCount: lines.length,
                        itemBuilder: (_, i) => SelectableText(lines[lines.length - 1 - i],
                            style: const TextStyle(fontFamily: 'Consolas', fontSize: 12)),
                      ),
                    );
                  },
                ),
              ),
            ),
          ]),
        ),
      ),
    ),
  );
}

// ---------------------------------------------------------------------------------------------- results
class _Results extends StatelessWidget {
  const _Results();
  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    return ResultsPane(
      results: app.results,
      version: app.resultsVersion,
      empty: app.scanning ? 'Results appear here as files are checked.' : 'Start a scan to see results here.',
    );
  }
}