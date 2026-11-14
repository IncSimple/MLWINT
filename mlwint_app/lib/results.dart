// MLWINT Flutter window: the results list + find box + filter + detail panel (Scan and History pages).
// Save as MLWINT/mlwint_app/lib/results.dart
// The list is virtualised (only visible rows are built), so a whole-PC scan with thousands of files scrolls smoothly.
// Right-click a row: plain text, Show in Explorer (only highlights the file, never opens it), copy path / SHA-256.
import 'package:material_ui/material_ui.dart';
import 'package:flutter/services.dart';

import 'platform/platform.dart';
import 'orb.dart';
import 'smooth.dart';
import 'state.dart';
import 'theme.dart';

enum Show { all, attention, notAnalysed, changed }

const showNames = {
  Show.all: 'All',
  Show.attention: 'Needs attention',
  Show.notAnalysed: 'Not analysed',
  Show.changed: 'Since last scan',
};

class ResultsPane extends StatefulWidget {
  final List<Json> results;
  final int version; // changes when results change
  final bool compare; // History: show the "since last scan" change
  final String empty;
  const ResultsPane({super.key, required this.results, required this.version, this.compare = false,
      this.empty = 'No results yet.'});
  @override
  State<ResultsPane> createState() => _ResultsPaneState();
}

class _ResultsPaneState extends State<ResultsPane> {
  final search = TextEditingController();
  Show show = Show.all;
  Json? selected;
  List<Json> rows = [];
  String _key = '';

  List<Json> _rows() {
    final key = '${widget.version}|${widget.results.length}|$show|${search.text}';
    if (key == _key) return rows;
    _key = key;
    final q = search.text.trim().toLowerCase();
    rows = [
      for (final r in widget.results)
        if ((q.isEmpty || r.path.toLowerCase().contains(q)) &&
            switch (show) {
              Show.all => true,
              Show.attention => r.flagged,
              Show.notAnalysed => !r.assessed,
              Show.changed => r.change.isNotEmpty,
            })
          r
    ]..sort(worstFirst);
    if (selected != null && !widget.results.contains(selected)) selected = null;
    return rows;
  }

  @override
  void didUpdateWidget(ResultsPane old) {
    super.didUpdateWidget(old);
    if (!identical(old.results, widget.results) || old.compare != widget.compare) {
      selected = null;
      if (!widget.compare && show == Show.changed) show = Show.all;
    }
  }

  @override
  void dispose() {
    search.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    final list = _rows();
    final first = list.isEmpty ? null : list.first;
    final current = selected ?? first;
    return LayoutBuilder(builder: (context, box) {
      final wide = box.maxWidth >= 980;
      final listView = Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(children: [
          Expanded(
            child: SizedBox(
              height: 44,
              child: SearchBar(
                controller: search,
                hintText: 'Find a file or folder',
                leading: const Icon(Icons.search, size: 20),
                elevation: const WidgetStatePropertyAll(0),
                backgroundColor: WidgetStatePropertyAll(s.surfaceContainer),
                padding: const WidgetStatePropertyAll(EdgeInsets.symmetric(horizontal: 14)),
                trailing: [
                  if (search.text.isNotEmpty)
                    IconButton(
                        icon: const Icon(Icons.close, size: 18),
                        onPressed: () => setState(search.clear),
                        tooltip: 'Clear'),
                ],
                onChanged: (_) => setState(() {}),
              ),
            ),
          ),
          const SizedBox(width: 12),
          Text('${list.length} of ${widget.results.length}', style: TextStyle(color: s.onSurfaceVariant, fontSize: 12)),
        ]),
        const SizedBox(height: 10),
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          child: Row(children: [
            for (final v in Show.values)
              if (v != Show.changed || widget.compare)
                Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: ChoiceChip(
                    label: Text(showNames[v]!),
                    selected: show == v,
                    showCheckmark: false,
                    onSelected: (_) => setState(() => show = v),
                  ),
                ),
          ]),
        ),
        const SizedBox(height: 10),
        Expanded(
          child: list.isEmpty
              ? Center(child: Text(widget.results.isEmpty ? widget.empty : 'Nothing matches.',
                  style: TextStyle(color: s.onSurfaceVariant)))
              : SmoothScroll(
                  builder: (context, controller) => ListView.builder(
                    controller: controller,
                    itemCount: list.length,
                    itemExtent: 74,
                    padding: const EdgeInsets.only(right: 18),
                    itemBuilder: (context, i) => _Row(
                      r: list[i],
                      selected: wide && identical(list[i], current),
                      compare: widget.compare,
                      onTap: () {
                        if (wide) {
                          setState(() => selected = list[i]);
                        } else {
                          showDetailDialog(context, list[i]);
                        }
                      },
                      onMenu: (pos) => rowMenu(context, list[i], pos),
                    ),
                  ),
                ),
        ),
      ]);
      if (!wide) return listView;
      return Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Expanded(child: listView),
        const SizedBox(width: 20),
        SizedBox(
          width: (box.maxWidth * 0.42).clamp(420.0, 560.0),
          child: AnimatedSwitcher(
            duration: Motion.medium,
            switchInCurve: Motion.enter,
            switchOutCurve: Motion.exit,
            transitionBuilder: (child, a) => FadeTransition(
                opacity: a,
                child: SlideTransition(
                    position: Tween(begin: const Offset(0.03, 0), end: Offset.zero).animate(a), child: child)),
            child: Detail(key: ValueKey(current), r: current),
          ),
        ),
      ]);
    });
  }
}

class _Row extends StatefulWidget {
  final Json r;
  final bool selected, compare;
  final VoidCallback onTap;
  final void Function(Offset) onMenu;
  const _Row({required this.r, required this.selected, required this.compare, required this.onTap,
      required this.onMenu});
  @override
  State<_Row> createState() => _RowState();
}

class _RowState extends State<_Row> {
  bool hover = false;
  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    final r = widget.r;
    final change = r.change;
    final worse = change.startsWith('worse') || change.startsWith('new');
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: MouseRegion(
        onEnter: (_) => setState(() => hover = true),
        onExit: (_) => setState(() => hover = false),
        child: GestureDetector(
          onSecondaryTapUp: (d) => widget.onMenu(d.globalPosition),
          child: AnimatedContainer(
            duration: Motion.short,
            curve: Motion.standard,
            decoration: BoxDecoration(
              color: widget.selected
                  ? s.surfaceContainerHigh
                  : hover
                      ? s.surfaceContainer
                      : s.surfaceContainerLow,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                  color: widget.selected ? colourOf(r.assessed ? r.level : null).withValues(alpha: 0.5) : Colors.transparent),
            ),
            child: Material(
              type: MaterialType.transparency,
              child: InkWell(
                borderRadius: BorderRadius.circular(16),
                onTap: widget.onTap,
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 12),
                  child: Row(children: [
                    ScoreBadge(r),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Column(mainAxisAlignment: MainAxisAlignment.center, crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                        Text(r.name, maxLines: 1, overflow: TextOverflow.ellipsis,
                            style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
                        const SizedBox(height: 3),
                        Text(
                          widget.compare && change.isNotEmpty ? '$change · ${r.headline}' : r.headline,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                              fontSize: 12.5,
                              color: widget.compare && worse ? colourOf('ELEVATED') : s.onSurfaceVariant),
                        ),
                      ]),
                    ),
                    const SizedBox(width: 12),
                    Column(mainAxisAlignment: MainAxisAlignment.center, crossAxisAlignment: CrossAxisAlignment.end,
                        children: [
                      r.assessed
                          ? LevelChip(r.level)
                          : Text('${r['status']}'.toUpperCase(),
                              style: TextStyle(fontSize: 11, color: s.onSurfaceVariant, letterSpacing: 1)),
                      const SizedBox(height: 5),
                      Text(r.howChecked, style: TextStyle(fontSize: 11, color: s.onSurfaceVariant)),
                    ]),
                  ]),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------------------------- actions
Future<void> rowMenu(BuildContext context, Json r, Offset at) async {
  final state = AppScope.read(context);
  final size = MediaQuery.sizeOf(context);
  final choice = await showMenu<String>(
    context: context,
    position: RelativeRect.fromLTRB(at.dx, at.dy, size.width - at.dx, size.height - at.dy),
    items: [
      const PopupMenuItem(value: 'text', child: ListTile(leading: Icon(Icons.article_outlined), title: Text('Show as plain text'))),
      const PopupMenuItem(
          value: 'reveal',
          child: ListTile(leading: Icon(Icons.folder_open_outlined), title: Text('Show in Explorer'),
              subtitle: Text('only highlights the file, never opens it'))),
      const PopupMenuItem(value: 'path', child: ListTile(leading: Icon(Icons.copy), title: Text('Copy path'))),
      if (r['sha256'] != null)
        const PopupMenuItem(value: 'sha', child: ListTile(leading: Icon(Icons.fingerprint), title: Text('Copy SHA-256'))),
    ],
  );
  if (!context.mounted || choice == null) return;
  try {
    switch (choice) {
      case 'text':
        final text = await state.engine.call<String>('text', {'result': r});
        if (context.mounted) showPlainText(context, r.name, text);
      case 'reveal':
        await state.engine.call('reveal', {'path': r.path});
      case 'path':
        await Clipboard.setData(ClipboardData(text: r.path));
        if (context.mounted) snack(context, 'Path copied');
      case 'sha':
        await Clipboard.setData(ClipboardData(text: '${r['sha256']}'));
        if (context.mounted) snack(context, 'SHA-256 copied');
    }
  } on EngineError catch (e) {
    if (context.mounted) snack(context, '$e', error: true);
  }
}

void showPlainText(BuildContext context, String name, String text) {
  showDialog(
    context: context,
    builder: (c) => Dialog(
      child: SizedBox(
        width: 900,
        height: 620,
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Row(children: [
              Expanded(child: Text('MLWINT report · $name', style: Theme.of(c).textTheme.titleLarge)),
              IconButton(
                  tooltip: 'Copy',
                  icon: const Icon(Icons.copy),
                  onPressed: () => Clipboard.setData(ClipboardData(text: text))),
              IconButton(tooltip: 'Close', icon: const Icon(Icons.close), onPressed: () => Navigator.pop(c)),
            ]),
            const SizedBox(height: 12),
            Expanded(
              child: Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                    color: Theme.of(c).colorScheme.surfaceContainerLowest, borderRadius: BorderRadius.circular(12)),
                child: SmoothScroll(
                    backToTop: false,
                    builder: (context, controller) => SingleChildScrollView(
                        controller: controller,
                        child: SelectableText(text, style: const TextStyle(fontFamily: 'Consolas', fontSize: 12.5, height: 1.4)))),
              ),
            ),
          ]),
        ),
      ),
    ),
  );
}

void showDetailDialog(BuildContext context, Json r) {
  showDialog(
    context: context,
    builder: (c) => Dialog(
      child: SizedBox(width: 620, height: 720, child: Padding(padding: const EdgeInsets.all(8), child: Detail(r: r))),
    ),
  );
}

/// Opens an https link (MITRE, MalwareBazaar, VirusTotal) in the default browser.
void openLink(String url) {
  if (url.startsWith('https://')) openUrl(url);
}

// ---------------------------------------------------------------------------------------------- detail
const _priority = {1: 'Now', 2: 'Clean up', 3: 'Protect', 4: 'Check'};

class Detail extends StatelessWidget {
  final Json? r;
  const Detail({super.key, required this.r});

  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    final t = Theme.of(context).textTheme;
    final animate = AppScope.of(context).animations;
    final r = this.r;
    if (r == null) {
      return Card(
        child: Center(
            child: Text('Select a file to see what MLWINT found.', style: TextStyle(color: s.onSurfaceVariant))),
      );
    }
    final ok = r.assessed;
    final adv = r.advice;
    Widget section(String title, List<Widget> children) => children.isEmpty
        ? const SizedBox.shrink()
        : Padding(
            padding: const EdgeInsets.only(top: 22),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Tag(title),
              const SizedBox(height: 10),
              ...children,
            ]),
          );
    Widget para(String text, {Color? colour, double size = 13.5}) => Padding(
        padding: const EdgeInsets.only(bottom: 6),
        child: Text(text, style: TextStyle(color: colour, fontSize: size, height: 1.45)));
    Widget bullet(String text, {Color? colour}) => Padding(
          padding: const EdgeInsets.only(bottom: 6),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Padding(
                padding: const EdgeInsets.only(top: 7, right: 10),
                child: Container(width: 5, height: 5, decoration: BoxDecoration(color: colour ?? s.primary, shape: BoxShape.circle))),
            Expanded(child: Text(text, style: const TextStyle(fontSize: 13.5, height: 1.45))),
          ]),
        );
    Widget link(String label, String url) => Padding(
          padding: const EdgeInsets.only(right: 8, bottom: 8),
          child: ActionChip(avatar: const Icon(Icons.open_in_new, size: 16), label: Text(label), onPressed: () => openLink(url)),
        );

    final parts = <Widget>[];
    // what to do
    final acts = [for (final a in (adv['actions'] as List? ?? const [])) (a as Map).cast<String, dynamic>()];
    final notes = [for (final n in (adv['notes'] as List? ?? const [])) '$n'];
    parts.add(section('What to do', [
      for (final a in acts)
        Container(
          margin: const EdgeInsets.only(bottom: 8),
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(color: s.surfaceContainer, borderRadius: BorderRadius.circular(14)),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            SizedBox(
              width: 74,
              child: Text(_priority[a['priority']] ?? '${a['priority']}',
                  style: TextStyle(color: s.primary, fontWeight: FontWeight.w700, fontSize: 12.5)),
            ),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('${a['action']}', style: const TextStyle(fontSize: 13.5, height: 1.4)),
                if (a['because'] != null)
                  Padding(
                    padding: const EdgeInsets.only(top: 4),
                    child: Text('because ${a['because']}', style: TextStyle(color: s.onSurfaceVariant, fontSize: 12.5)),
                  ),
              ]),
            ),
          ]),
        ),
      for (final n in notes) bullet(n, colour: s.onSurfaceVariant),
    ]));
    if (ok) {
      // why this score
      final prob = r['probability'];
      final limits = <String>[
        if (r['floor'] != null && r['floor'] != 0) 'never below ${r['floor']} (detector verdict ${r['verdict']})',
        if ((r['cap'] as num? ?? 100) < 100) 'capped at ${r['cap']}: a PDF with nothing that can run',
      ];
      parts.add(section('Why this score', [
        para('${r['format']} file · detector verdict ${r['verdict']}'
            '${prob is num ? ' · malware probability ${(prob * 100).toStringAsFixed(1)}%' : ''}',
            colour: s.onSurfaceVariant, size: 12.5),
        for (final p in (r['parts'] as List? ?? const []))
          _PartRow(points: (p['points'] as num).toDouble(), part: '${p['part']}', reason: '${p['reason']}'),
        for (final l in limits) para(l, colour: s.onSurfaceVariant, size: 12.5),
      ]));
      // family / behaviour
      final fam = r['family'] as Map?;
      final beh = r['behaviours'] as List? ?? const [];
      parts.add(section('Family and behaviour', [
        if (fam != null)
          para('Family: ${fam['name']} (confidence ${(((fam['confidence'] as num?) ?? 0) * 100).round()}%; '
              'right ${(((fam['test_precision'] as num?) ?? 0) * 100).round()}% of the time on test)'),
        if (beh.isNotEmpty)
          Wrap(spacing: 8, runSpacing: 8, children: [
            for (final b in beh) Chip(label: Text('${b['tag']} · ${b['tier']}')),
          ]),
      ]));
      // ATT&CK
      parts.add(section('What it can do · MITRE ATT&CK', [
        for (final a in (r['attack'] as List? ?? const []))
          _Technique(a: (a as Map).cast<String, dynamic>()),
      ]));
      // this PC
      final facts = ((r['local_context'] as Map?)?['facts'] as List?) ?? const [];
      parts.add(section('On this PC', [for (final f in facts) bullet('$f')]));
      // deep check
      final dc = r['deep_check'] as Map?;
      if (dc != null) {
        final found = dc['findings'] as List? ?? const [];
        final servers = ((dc['observed'] as Map?)?['servers'] as List?) ?? const [];
        parts.add(section('Deep check (safe simulation)', [
          para('Emulation: ${dc['status']}${dc['status'] != 'completed' ? ' · ${dc['reason']}' : ''}'),
          for (final f in found.take(10)) bullet('${f['title']}', colour: colourOf('ELEVATED')),
          if (servers.isNotEmpty) para('Tried to contact: ${servers.take(10).join(', ')}'),
        ]));
      } else if (r['deep_check_reason'] != null) {
        parts.add(section('Deep check (safe simulation)',
            [para('not run: ${r['deep_check_reason']}', colour: s.onSurfaceVariant, size: 12.5)]));
      }
      // outside opinion
      final rep = (r['reputation'] as Map?) ?? const {};
      parts.add(section('Outside opinion', [
        Wrap(children: [
          for (final e in rep.entries)
            if ((e.value as Map?)?['link'] != null) link('${e.key}', '${(e.value as Map)['link']}'),
        ]),
      ].where((_) => rep.values.any((v) => (v as Map?)?['link'] != null)).toList()));
    }
    // file facts
    final sig = (r['signature'] as Map?) ?? const {};
    final ds = (r['defender_scan'] as Map?) ?? const {};
    parts.add(section('File', [
      if (r['remembered'] is Map)
        para('Remembered: unchanged since the check on ${r['remembered']['day']}. That result was used; the PC facts '
            'were refreshed now.', colour: s.onSurfaceVariant, size: 12.5),
      if (r['large_file'] == true)
        para('Large-file check: signature, a report-only Microsoft Defender scan '
            '(${ds['status'] == 'clean' ? 'no threat found' : ds['status'] == 'detected' ? 'DETECTED: ${(ds['threats'] as List? ?? []).join(', ')}' : 'not available'}), '
            'detector at half weight.', colour: s.onSurfaceVariant, size: 12.5),
      if (sig['status'] != null && sig['status'] != 'not checked')
        para('Digital signature: ${sig['status']}${sig['signer'] != null ? ' (${sig['signer']})' : ''}',
            colour: s.onSurfaceVariant, size: 12.5),
      para(r.path, colour: s.onSurfaceVariant, size: 12.5),
      if (r['sha256'] != null) para('SHA-256 ${r['sha256']}', colour: s.onSurfaceVariant, size: 11.5),
      if (!ok) para('Not analysed (${r['status']}): ${r['reason']}'),
    ]));

    return Card(
      color: s.surfaceContainerLow,
      child: SelectionArea(
        child: SmoothScroll(backToTop: false, builder: (context, controller) => CustomScrollView(controller: controller, slivers: [
          SliverPadding(
            padding: const EdgeInsets.fromLTRB(24, 20, 24, 28),
            sliver: SliverList.list(children: [
              Row(children: [
                SizedBox(
                  width: 150,
                  height: 150,
                  child: ThreatOrb(score: ok ? r.score : null, level: r.level, compact: true, animate: animate),
                ),
                const SizedBox(width: 18),
                Expanded(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text(r.name, style: t.headlineSmall?.copyWith(fontSize: 21), maxLines: 3),
                    const SizedBox(height: 8),
                    Row(children: [
                      if (ok) LevelChip(r.level),
                      if (ok) const SizedBox(width: 8),
                      Flexible(
                          child: Text(ok ? '${r['format']}' : '${r['status']}'.toUpperCase(),
                              style: TextStyle(color: s.onSurfaceVariant, fontSize: 12.5))),
                    ]),
                  ]),
                ),
              ]),
              const SizedBox(height: 14),
              Text(r.headline, style: t.titleMedium?.copyWith(height: 1.4)),
              if (ok && adv['headline'] != null && r['summary'] != null)
                Padding(
                  padding: const EdgeInsets.only(top: 6),
                  child: Text('${r['summary']}', style: TextStyle(color: s.onSurfaceVariant, height: 1.45)),
                ),
              ...parts,
            ]),
          ),
        ])),
      ),
    );
  }
}

class _PartRow extends StatelessWidget {
  final double points;
  final String part, reason;
  const _PartRow({required this.points, required this.part, required this.reason});
  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    final c = points > 0 ? colourOf('SEVERE') : points < 0 ? colourOf('LOW') : s.onSurfaceVariant;
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        SizedBox(
          width: 54,
          child: Text('${points > 0 ? '+' : ''}${points.toStringAsFixed(1)}',
              textAlign: TextAlign.right, style: TextStyle(color: c, fontWeight: FontWeight.w700, fontSize: 13)),
        ),
        const SizedBox(width: 14),
        Expanded(
          child: Text.rich(TextSpan(children: [
            TextSpan(text: '$part  ', style: const TextStyle(fontWeight: FontWeight.w600)),
            TextSpan(text: reason, style: TextStyle(color: s.onSurfaceVariant)),
          ]), style: const TextStyle(fontSize: 13, height: 1.4)),
        ),
      ]),
    );
  }
}

class _Technique extends StatelessWidget {
  final Json a;
  const _Technique({required this.a});
  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    final e = (a['explanation'] as Map?) ?? const {};
    final id = '${a['id']}';
    final url = '${e['url'] ?? 'https://attack.mitre.org/techniques/${id.replaceAll('.', '/')}/'}';
    var summary = '${e['summary'] ?? ''}';
    if (summary.length > 280) summary = '${summary.substring(0, 280)}…';
    final mit = [for (final m in ((e['mitigations'] as List?) ?? const []).take(3)) '${m['id']} ${m['name']}'];
    final sources = {...((a['sources'] as List?) ?? const []).map((x) => '$x')}.toList()..sort();
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(color: s.surfaceContainer, borderRadius: BorderRadius.circular(14)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          InkWell(
            onTap: () => openLink(url),
            borderRadius: BorderRadius.circular(6),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
              child: Text(id, style: TextStyle(color: s.primary, fontWeight: FontWeight.w700, fontSize: 12.5)),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(child: Text('${a['technique']}', style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13.5))),
        ]),
        Padding(
          padding: const EdgeInsets.only(top: 4, left: 4),
          child: Text('${a['tactic']} · seen by ${sources.join('/')}',
              style: TextStyle(color: s.onSurfaceVariant, fontSize: 12)),
        ),
        if (summary.isNotEmpty)
          Padding(
              padding: const EdgeInsets.only(top: 6, left: 4),
              child: Text(summary, style: const TextStyle(fontSize: 12.5, height: 1.45))),
        if (mit.isNotEmpty)
          Padding(
              padding: const EdgeInsets.only(top: 6, left: 4),
              child: Text('MITRE mitigations: ${mit.join('; ')}',
                  style: TextStyle(color: s.onSurfaceVariant, fontSize: 12))),
      ]),
    );
  }
}