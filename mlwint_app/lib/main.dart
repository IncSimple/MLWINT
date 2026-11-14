// MLWINT Flutter window (Material 3). Save as MLWINT/mlwint_app/lib/main.dart
// Starts the Python engine (scripts/mlwint_engine.py) and shows five pages in a navigation rail:
// Dashboard, Scan, History, Settings, Help. Pages change with the M3 "fade through" motion.
// Read-only like the rest of MLWINT: nothing is deleted, moved, quarantined, run or uploaded.
import 'dart:ui';

import 'package:material_ui/material_ui.dart';

import 'pages/dashboard.dart';
import 'pages/help.dart';
import 'pages/history.dart';
import 'pages/scan.dart';
import 'pages/settings.dart';
import 'platform/platform.dart';
import 'smooth.dart';
import 'state.dart';
import 'theme.dart';

void main() {
  final state = AppState();
  // Any error in the window goes to the Scan page's log and to MLWINT\reports\app-errors.txt (never hidden).
  void record(Object error, StackTrace? stack) {
    final text = '${DateTime.now()}  $error\n$stack\n';
    state.addLog('WINDOW ERROR: $error');
    appendErrorLog(state.engine.root, text);
  }

  FlutterError.onError = (d) => record(d.exception, d.stack);
  PlatformDispatcher.instance.onError = (e, s) {
    record(e, s);
    return true;
  };
  runApp(AppScope(state: state, child: const MlwintApp()));
  state.start();
}

class MlwintApp extends StatelessWidget {
  const MlwintApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'MLWINT',
        debugShowCheckedModeBanner: false,
        theme: buildTheme(),
        darkTheme: buildTheme(),
        themeMode: ThemeMode.dark,
        scrollBehavior: const NoScrollbars(), // no classic scrollbars anywhere (see smooth.dart)
        home: const Shell(),
      );
}

const destinations = [
  ('Dashboard', Icons.space_dashboard_outlined, Icons.space_dashboard),
  ('Scan', Icons.radar_outlined, Icons.radar),
  ('History', Icons.history_outlined, Icons.history),
  ('Settings', Icons.tune_outlined, Icons.tune),
  ('Help', Icons.help_outline, Icons.help),
];

class Shell extends StatefulWidget {
  const Shell({super.key});
  @override
  State<Shell> createState() => _ShellState();
}

class _ShellState extends State<Shell> {
  late final AppLifecycleListener _life;

  @override
  void initState() {
    super.initState();
    _life = AppLifecycleListener(onExitRequested: _onExit);
  }

  @override
  void dispose() {
    _life.dispose();
    super.dispose();
  }

  Future<AppExitResponse> _onExit() async {
    final app = AppScope.read(context);
    if (app.scanning &&
        !await confirm(context, 'A scan is running', 'Stop it and close MLWINT? The files checked so far are '
            'remembered.', yes: 'Stop and close')) {
      return AppExitResponse.cancel;
    }
    await app.keepOptions();
    await app.engine.quit();
    return AppExitResponse.exit;
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = Theme.of(context).colorScheme;
    smoothScrolling = app.animations; // the Animations setting also switches eased scrolling
    if (app.starting || (app.startError != null && app.hello.isEmpty)) return const _Startup();
    return ValueListenableBuilder<int>(
      valueListenable: app.page,
      builder: (context, page, _) {
        final wide = MediaQuery.sizeOf(context).width >= 1360;
        return Scaffold(
          body: Row(children: [
            NavigationRail(
              extended: wide,
              minExtendedWidth: 220,
              selectedIndex: page,
              labelType: wide ? NavigationRailLabelType.none : NavigationRailLabelType.all,
              onDestinationSelected: (i) => app.page.value = i,
              leading: Padding(
                padding: const EdgeInsets.fromLTRB(8, 18, 8, 28),
                child: _Logo(extended: wide),
              ),
              trailingAtBottom: true,
              trailing: Padding(padding: const EdgeInsets.only(bottom: 22), child: _Status(extended: wide)),
              destinations: [
                for (final (i, (name, icon, selected)) in destinations.indexed)
                  NavigationRailDestination(
                    icon: i == 1 && app.scanning
                        ? Badge(smallSize: 8, backgroundColor: s.primary, child: Icon(icon))
                        : Icon(icon),
                    selectedIcon: Icon(selected),
                    label: Text(name),
                  ),
              ],
            ),
            const VerticalDivider(width: 1),
            Expanded(
              child: Stack(children: [
                // M3 fade through: the old page fades out, the new one fades in while growing from 96 %
                PageTransitionSwitcher(
                  index: page,
                  children: const [DashboardPage(), ScanPage(), HistoryPage(), SettingsPage(), HelpPage()],
                ),
                if (app.startError != null)
                  Positioned(
                    left: 24,
                    right: 24,
                    bottom: 24,
                    child: MaterialBanner(
                      backgroundColor: s.errorContainer,
                      content: Text(app.startError!, style: TextStyle(color: s.onErrorContainer)),
                      actions: [TextButton(onPressed: app.restart, child: const Text('Restart engine'))],
                    ),
                  ),
              ]),
            ),
          ]),
        );
      },
    );
  }
}

/// Keeps every page alive (scroll position, typed text) and plays the M3 fade-through when the page changes.
/// Hidden pages are not painted and their animations are paused (TickerMode).
class PageTransitionSwitcher extends StatefulWidget {
  final int index;
  final List<Widget> children;
  const PageTransitionSwitcher({super.key, required this.index, required this.children});
  @override
  State<PageTransitionSwitcher> createState() => _PageTransitionSwitcherState();
}

class _PageTransitionSwitcherState extends State<PageTransitionSwitcher> with SingleTickerProviderStateMixin {
  late final c = AnimationController(vsync: this, duration: Motion.medium, value: 1);
  late int shown = widget.index, previous = widget.index;
  final built = <int>{};

  @override
  void didUpdateWidget(PageTransitionSwitcher old) {
    super.didUpdateWidget(old);
    if (widget.index != shown) {
      previous = shown;
      shown = widget.index;
      c.forward(from: 0);
    }
  }

  @override
  void dispose() {
    c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    built.add(shown);
    return AnimatedBuilder(
      animation: c,
      builder: (context, _) {
        final v = c.value;
        final outgoing = v < 0.35 && previous != shown; // first 35 %: old page fades out
        final inT = Motion.enter.transform(((v - 0.35) / 0.65).clamp(0.0, 1.0));
        return Stack(fit: StackFit.expand, children: [
          for (var i = 0; i < widget.children.length; i++)
            if (built.contains(i))
              _page(
                i,
                visible: i == shown ? (previous == shown ? 1.0 : inT) : (i == previous && outgoing ? 1 - v / 0.35 : 0.0),
                scale: i == shown && previous != shown ? 0.96 + 0.04 * inT : 1.0,
              ),
        ]);
      },
    );
  }

  Widget _page(int i, {required double visible, required double scale}) {
    final on = visible > 0;
    return Offstage(
      offstage: !on,
      child: TickerMode(
        enabled: on,
        child: IgnorePointer(
          ignoring: i != shown,
          child: Opacity(
            opacity: visible.clamp(0.0, 1.0),
            child: Transform.scale(scale: scale, child: KeyedSubtree(key: ValueKey(i), child: widget.children[i])),
          ),
        ),
      ),
    );
  }
}

class _Logo extends StatelessWidget {
  final bool extended;
  const _Logo({required this.extended});
  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    final mark = Container(
      width: 40,
      height: 40,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(12),
        gradient: LinearGradient(colors: [s.primary, s.primary.withValues(alpha: 0.55)],
            begin: Alignment.topLeft, end: Alignment.bottomRight),
      ),
      child: Icon(Icons.shield_moon_outlined, color: s.onPrimary, size: 22),
    );
    if (!extended) return mark;
    return SizedBox(
      width: 190,
      child: Row(children: [
        mark,
        const SizedBox(width: 12),
        Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Text('MLWINT', style: TextStyle(fontFamily: display, fontSize: 20, fontWeight: FontWeight.w600, letterSpacing: 1)),
          Text('malware intelligence', style: TextStyle(color: s.onSurfaceVariant, fontSize: 11)),
        ]),
      ]),
    );
  }
}

class _Status extends StatelessWidget {
  final bool extended;
  const _Status({required this.extended});
  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = Theme.of(context).colorScheme;
    final lookup = '${app.scanOptions['reputation'] ?? 'off'}' != 'off';
    final dot = Container(
        width: 8, height: 8, decoration: BoxDecoration(color: app.engine.running ? s.primary : s.error, shape: BoxShape.circle));
    if (!extended) return Tooltip(message: app.engine.running ? 'Engine running · read-only' : 'Engine stopped', child: dot);
    return SizedBox(
      width: 190,
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        if (app.engine.demo) ...[
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
            decoration: BoxDecoration(
                color: s.primary.withValues(alpha: 0.12), borderRadius: BorderRadius.circular(20),
                border: Border.all(color: s.primary.withValues(alpha: 0.35))),
            child: Text('LIVE DEMO · sample data',
                style: TextStyle(color: s.primary, fontSize: 10.5, fontWeight: FontWeight.w700, letterSpacing: 1)),
          ),
          const SizedBox(height: 10),
          FilledButton.icon(
            style: FilledButton.styleFrom(minimumSize: const Size(190, 42), padding: EdgeInsets.zero),
            onPressed: () => openUrl('https://github.com/IncSimple/MLWINT/releases/latest'),
            icon: const Icon(Icons.download_rounded, size: 18),
            label: const Text('Download for Windows'),
          ),
          const SizedBox(height: 16),
        ],
        Row(children: [dot, const SizedBox(width: 8), Text(app.engine.demo ? 'Demo engine' : (app.engine.running ? 'Engine running' : 'Engine stopped'))]),
        const SizedBox(height: 6),
        Text('Read-only · hash lookup ${lookup ? 'on' : 'off'}\n${app.memoryCount} files remembered',
            style: TextStyle(color: s.onSurfaceVariant, fontSize: 11.5, height: 1.4)),
      ]),
    );
  }
}

class _Startup extends StatelessWidget {
  const _Startup();
  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = Theme.of(context).colorScheme;
    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 620),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Tag('MLWINT'),
            const SizedBox(height: 12),
            Text(app.startError == null ? 'Starting the engine…' : 'The engine could not start',
                style: Theme.of(context).textTheme.headlineMedium),
            const SizedBox(height: 18),
            if (app.startError == null)
              const LinearProgressIndicator()
            else ...[
              Text(app.startError!, style: TextStyle(color: s.error, height: 1.5)),
              const SizedBox(height: 12),
              Container(
                height: 200,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(color: s.surfaceContainerLowest, borderRadius: BorderRadius.circular(12)),
                child: SingleChildScrollView(
                  reverse: true,
                  child: SelectableText(app.log.join('\n'), style: const TextStyle(fontFamily: 'Consolas', fontSize: 11.5)),
                ),
              ),
              const SizedBox(height: 16),
              FilledButton.icon(onPressed: app.restart, icon: const Icon(Icons.refresh), label: const Text('Try again')),
            ],
          ]),
        ),
      ),
    );
  }
}