// MLWINT Flutter window: Settings page. Save as MLWINT/mlwint_app/lib/pages/settings.dart
//   hash lookup keys (yours, saved only on this PC; Test sends ONE harmless public hash), scan options and
//   animations, memory, health check, privacy. (The models folder is a developer setting: config file only.)
import 'package:material_ui/material_ui.dart';

import '../state.dart';
import '../smooth.dart';
import '../theme.dart';

class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});
  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  final keyEdits = <String, TextEditingController>{};
  bool showKeys = false, testing = false;
  double? days;

  @override
  void dispose() {
    for (final c in keyEdits.values) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> run(Future<void> Function() f) async {
    try {
      await f();
    } on EngineError catch (e) {
      if (mounted) snack(context, '$e', error: true);
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = Theme.of(context).colorScheme;
    final set = app.settings;
    final range = (app.hello['memory_days_range'] as List?) ?? const [1, 365];
    final memDays = days ?? ((set['memory_days'] as num?) ?? 30).toDouble();
    return SmoothScroll(builder: (context, controller) => ListView(
      controller: controller,
      padding: const EdgeInsets.fromLTRB(36, 28, 36, 40),
      children: [
        Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 940),
            child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              const Tag('Preferences'),
              const SizedBox(height: 8),
              Text('Settings', style: Theme.of(context).textTheme.headlineMedium),
              const SizedBox(height: 22),
              // ---- keys
              Reveal(child: Section(
                tag: '01',
                title: 'Hash lookup keys',
                trailing: IconButton(
                  tooltip: showKeys ? 'Hide' : 'Show while typing',
                  onPressed: () => setState(() => showKeys = !showKeys),
                  icon: Icon(showKeys ? Icons.visibility_off_outlined : Icons.visibility_outlined),
                ),
                child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  for (final k in app.keys) ...[
                    TextField(
                      controller: keyEdits.putIfAbsent('${k['name']}', TextEditingController.new),
                      obscureText: !showKeys,
                      enabled: !app.scanning,
                      decoration: InputDecoration(
                        labelText: '${k['label']}',
                        helperText: '${k['help']}',
                        suffixText: '${k['state']}',
                      ),
                    ),
                    if ('${k['env']}'.isNotEmpty)
                      Padding(
                        padding: const EdgeInsets.only(top: 4),
                        child: Text('${k['env']} is set in your environment and is used instead of the saved key.',
                            style: TextStyle(color: colourOf('ELEVATED'), fontSize: 12)),
                      ),
                    const SizedBox(height: 14),
                  ],
                  Wrap(spacing: 10, runSpacing: 10, children: [
                    FilledButton(
                      onPressed: app.scanning
                          ? null
                          : () => run(() async {
                                final keys = {for (final e in keyEdits.entries) e.key: e.value.text};
                                app.keys = [
                                  for (final k in (await app.engine.call<List>('keys_save', {'keys': keys})))
                                    (k as Map).cast<String, dynamic>()
                                ];
                                for (final c in keyEdits.values) {
                                  c.clear();
                                }
                                await app.refreshStatus();
                                if (context.mounted) snack(context, 'Keys saved on this PC.');
                              }),
                      child: const Text('Save keys'),
                    ),
                    OutlinedButton(
                      onPressed: testing || !app.keys.any((k) => k['saved'] == true || '${k['env']}'.isNotEmpty)
                          ? null
                          : () => run(() async {
                                setState(() => testing = true);
                                try {
                                  final r = await app.engine.call<Json>('keys_test');
                                  if (!context.mounted) return;
                                  await showDialog(
                                    context: context,
                                    builder: (c) => AlertDialog(
                                      title: const Text('Key test'),
                                      content: Text('${(r['lines'] as List).join('\n')}\n\nOnly the EICAR test '
                                          'fingerprint was sent.\nIn the meter this would read: ${r['meter']}'),
                                      actions: [TextButton(onPressed: () => Navigator.pop(c), child: const Text('OK'))],
                                    ),
                                  );
                                } finally {
                                  if (mounted) setState(() => testing = false);
                                }
                              }),
                      child: Text(testing ? 'Testing…' : 'Test keys'),
                    ),
                    TextButton(
                      onPressed: !app.keys.any((k) => k['saved'] == true)
                          ? null
                          : () => run(() async {
                                if (!await confirm(context, 'Remove the saved keys?',
                                    'Hash lookup stays off until you add a key again.', yes: 'Remove')) {
                                  return;
                                }
                                await app.engine.call('keys_remove');
                                await app.refreshStatus();
                              }),
                      child: const Text('Remove saved keys'),
                    ),
                  ]),
                  const SizedBox(height: 10),
                  Text('Saved only on this PC in config\\intel_keys.json. Never share, upload or commit that file.',
                      style: TextStyle(color: s.onSurfaceVariant, fontSize: 12.5)),
                ]),
              )),
              const SizedBox(height: 18),
              // ---- options
              Reveal(child: Section(
                tag: '02',
                title: 'Scan options and look',
                child: Column(children: [
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Keep my scan choices and folders between sessions'),
                    value: set['remember_options'] != false,
                    onChanged: (v) => run(() => app.setSetting('remember_options', v)),
                  ),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Animations'),
                    subtitle: const Text('Smooth scrolling, the moving orb, light streaks and reveals. Switch off on slow PCs.'),
                    value: app.animations,
                    onChanged: (v) => run(() => app.setSetting('animations', v)),
                  ),
                  Align(
                    alignment: Alignment.centerLeft,
                    child: TextButton.icon(
                      onPressed: app.scanning
                          ? null
                          : () => run(() async {
                                app.scanOptions = await app.engine.call<Json>('reset_options');
                                app.changed();
                                if (context.mounted) snack(context, 'Scan options reset to the defaults.');
                              }),
                      icon: const Icon(Icons.restart_alt, size: 18),
                      label: const Text('Reset scan options'),
                    ),
                  ),
                ]),
              )),
              const SizedBox(height: 18),
              // ---- memory
              Reveal(child: Section(
                tag: '03',
                title: 'Memory',
                child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  Text('Unchanged files that were checked before are not analysed again. ${app.memoryCount} files '
                      'remembered now.', style: TextStyle(color: s.onSurfaceVariant, height: 1.45)),
                  const SizedBox(height: 12),
                  Row(children: [
                    const Text('Check a remembered file again after'),
                    Expanded(
                      child: Slider(
                        min: (range[0] as num).toDouble(),
                        max: (range[1] as num).toDouble(),
                        value: memDays.clamp((range[0] as num).toDouble(), (range[1] as num).toDouble()),
                        label: '${memDays.round()} days',
                        divisions: (range[1] as num).toInt() - (range[0] as num).toInt(),
                        onChanged: (v) => setState(() => days = v),
                        onChangeEnd: (v) => run(() async {
                          await app.setSetting('memory_days', v.round());
                          days = null;
                        }),
                      ),
                    ),
                    SizedBox(width: 70, child: Text('${memDays.round()} days', textAlign: TextAlign.right)),
                  ]),
                  const SizedBox(height: 6),
                  Align(
                    alignment: Alignment.centerLeft,
                    child: OutlinedButton.icon(
                      onPressed: app.scanning
                          ? null
                          : () => run(() async {
                                if (!await confirm(context, 'Forget all remembered results?',
                                    'The next scan will analyse every file again. Only MLWINT\'s own memory file is cleared.',
                                    yes: 'Forget')) {
                                  return;
                                }
                                await app.engine.call('forget');
                                await app.refreshStatus();
                              }),
                      icon: const Icon(Icons.delete_sweep_outlined, size: 18),
                      label: const Text('Forget remembered results'),
                    ),
                  ),
                ]),
              )),
              const SizedBox(height: 18),
              // ---- health
              Reveal(child: Section(
                tag: '04',
                title: 'Health check',
                trailing: IconButton(tooltip: 'Check again', onPressed: app.refreshHealth, icon: const Icon(Icons.refresh)),
                child: Column(children: [
                  for (final h in app.health)
                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      dense: true,
                      leading: Icon(h['ok'] == true ? Icons.check_circle : Icons.error_outline,
                          color: h['ok'] == true ? s.primary : s.error),
                      title: Text('${h['part']}'),
                      subtitle: Text('${h['detail']}', maxLines: 1, overflow: TextOverflow.ellipsis),
                    ),
                ]),
              )),
              const SizedBox(height: 18),
              // ---- privacy
              Reveal(child: Section(
                tag: '05',
                title: 'Privacy',
                child: Text(
                  '${app.hello['privacy'] ?? ''}'.replaceAll(RegExp(r'<br>'), '\n').replaceAll(RegExp(r'<[^>]+>'), ''),
                  style: const TextStyle(height: 1.6),
                ),
              )),
            ]),
          ),
        ),
      ],
    ));
  }
}