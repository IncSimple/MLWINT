// MLWINT Flutter window: Help & About. Save as MLWINT/mlwint_app/lib/pages/help.dart
//   "How MLWINT checks a file": five equal, short cards (icon + title). The card under the pointer drops down like a
//   menu over the page to reveal its explanation; a soft glow walks from card to card when nothing is open.
import 'dart:math' as math;

import 'package:material_ui/material_ui.dart';

import '../smooth.dart';
import '../state.dart';
import '../theme.dart';

const steps = [
  ('Detector', Icons.psychology_outlined,
      'A model trained on hundreds of thousands of known safe and harmful Windows programs and PDFs says how similar the file is to known malware.'),
  ('Code check', Icons.code,
      'For flagged and risky files, capa reads the program\'s code and lists what it can do, mapped to MITRE ATT&CK. PDFs are checked for JavaScript, launch actions and hidden files.'),
  ('Safe simulation', Icons.science_outlined,
      'Speakeasy imitates Windows and watches what a program would try to do, without ever really running it.'),
  ('Your PC', Icons.computer,
      'Where the file came from, whether it was ever run, whether it is running or starts automatically, and what Microsoft Defender already knows.'),
  ('Outside opinion', Icons.travel_explore,
      'Optional and off by default: only the file\'s SHA-256 fingerprint is looked up at MalwareBazaar / VirusTotal with your own key.'),
];
const levelHelp = [
  ('LOW', 'below 20', 'No meaningful sign of malware.'),
  ('GUARDED', '20 – 39', 'Weak warning signs. Fine if you expected the file.'),
  ('ELEVATED', '40 – 59', 'Clear warning signs. Do not open it until you know where it came from.'),
  ('HIGH', '60 – 79', 'Very likely malware. Follow the steps in the report.'),
  ('SEVERE', '80 – 100', 'Malware with harmful behaviour. Follow the steps in the report now.'),
];
const credits = [
  ('capa', 'Mandiant FLARE · reads what a program can do', 'Apache License 2.0'),
  ('Speakeasy', 'Mandiant · safe simulation of Windows programs', 'MIT License'),
  ('MITRE ATT&CK', 'The MITRE Corporation · names and explains attacker techniques', '© The MITRE Corporation, used under its terms of use'),
  ('EMBER2024', 'the file features the detectors read', 'see the EMBER2024 project licence'),
  ('XGBoost · LightGBM', 'the machine-learning models', 'Apache License 2.0 / MIT License'),
  ('Flutter', 'this window (Material 3)', 'BSD 3-Clause'),
  ('Qt for Python', 'PySide6 · the PDF reports', 'LGPL v3'),
];

class HelpPage extends StatelessWidget {
  const HelpPage({super.key});
  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = Theme.of(context).colorScheme;
    return SmoothScroll(
      builder: (context, controller) => ListView(controller: controller, padding: const EdgeInsets.fromLTRB(36, 28, 36, 40), children: [
        const Tag('Guide'),
        const SizedBox(height: 14),
        Headline('How MLWINT', 'keeps an eye on your files', size: 40, animate: app.animations),
        const SizedBox(height: 10),
        Text('Point at a step to see what it does.', style: TextStyle(color: s.onSurfaceVariant)),
        const SizedBox(height: 22),
        Reveal(child: _Steps(animate: app.animations)),
        const SizedBox(height: 22),
        Reveal(
          child: Section(
            tag: 'Levels',
            title: 'What the score means',
            child: Column(children: [
              for (final (l, range, text) in levelHelp)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: SizedBox(width: 120, child: Align(alignment: Alignment.centerLeft, child: LevelChip(l))),
                  title: Text(text),
                  trailing: Text(range, style: TextStyle(color: s.onSurfaceVariant)),
                ),
            ]),
          ),
        ),
        const SizedBox(height: 22),
        Reveal(
          child: Section(
            tag: 'Privacy',
            title: 'Read-only, always',
            child: Text(
              'MLWINT reads files to check them and writes only its own reports, memory and settings. It never deletes, '
              'moves, quarantines, runs or uploads your files: every step in a report is for you to do. Nothing leaves '
              'this PC unless you switch Hash lookup on; then only SHA-256 fingerprints are sent, never the file, its '
              'name or its folder.',
              style: TextStyle(color: s.onSurfaceVariant, height: 1.6),
            ),
          ),
        ),
        const SizedBox(height: 22),
        Reveal(
          child: Section(
            tag: 'About',
            title: 'MLWINT ${(app.hello['versions'] as Map?)?['app'] ?? ''}',
            child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: Text('Detection models ${(app.hello['versions'] as Map?)?['models'] ?? ''}',
                    style: TextStyle(color: s.onSurfaceVariant)),
              ),
              for (final (name, what, licence) in credits)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  dense: true,
                  title: Text(name, style: const TextStyle(fontWeight: FontWeight.w600)),
                  subtitle: Text(what),
                  trailing: Text(licence, style: TextStyle(color: s.onSurfaceVariant, fontSize: 12)),
                ),
            ]),
          ),
        ),
      ]),
    );
  }
}

// ---------------------------------------------------------------------------------------------- the five steps
const _cardHeight = 176.0;

/// Five equal, short cards (icon + title). Pointing at one drops it down like a menu over the page to show what the
/// step does; a soft glow walks from card to card while nothing is open.
class _Steps extends StatefulWidget {
  final bool animate;
  const _Steps({required this.animate});
  @override
  State<_Steps> createState() => _StepsState();
}

class _StepsState extends State<_Steps> with TickerProviderStateMixin {
  late final glow = AnimationController(vsync: this, duration: Duration(milliseconds: 1600 * steps.length));
  late final drop = AnimationController(vsync: this, duration: Motion.long, reverseDuration: Motion.medium);
  late final dropCurve = CurvedAnimation(parent: drop, curve: Motion.enter, reverseCurve: Motion.exit);
  final links = [for (final _ in steps) LayerLink()];
  final portal = OverlayPortalController();
  int? open;
  double cardWidth = 0;

  @override
  void initState() {
    super.initState();
    if (widget.animate) glow.repeat();
  }

  @override
  void didUpdateWidget(_Steps old) {
    super.didUpdateWidget(old);
    if (widget.animate && !glow.isAnimating) glow.repeat();
    if (!widget.animate) glow.stop();
  }

  @override
  void dispose() {
    glow.dispose();
    dropCurve.dispose();
    drop.dispose();
    super.dispose();
  }

  void show(int i) {
    if (open != i) {
      setState(() => open = i);
      drop.value = 0;
    }
    portal.show();
    drop.forward();
  }

  Future<void> hide() async {
    try {
      await drop.reverse().orCancel;
    } on TickerCanceled {
      return; // another card opened meanwhile
    }
    if (mounted && drop.value == 0) {
      portal.hide();
      setState(() => open = null);
    }
  }

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(builder: (context, box) {
      const gap = 16.0;
      cardWidth = (box.maxWidth - gap * (steps.length - 1)) / steps.length;
      return OverlayPortal(
        controller: portal,
        overlayChildBuilder: (_) => open == null ? const SizedBox.shrink() : _dropdown(open!),
        child: SizedBox(
          height: _cardHeight,
          child: Row(children: [
            for (var i = 0; i < steps.length; i++) ...[
              if (i > 0) const SizedBox(width: gap),
              CompositedTransformTarget(
                link: links[i],
                child: MouseRegion(
                  onEnter: (_) => show(i),
                  child: SizedBox(
                    width: cardWidth,
                    height: _cardHeight,
                    child: _StepCard(index: i, glow: glow, glowOn: open == null && widget.animate),
                  ),
                ),
              ),
            ],
          ]),
        ),
      );
    });
  }

  /// The open card, drawn above the page at the same spot, growing downward.
  Widget _dropdown(int i) => Align(
        alignment: Alignment.topLeft,
        child: CompositedTransformFollower(
          link: links[i],
          showWhenUnlinked: false,
          child: MouseRegion(
            onExit: (_) => hide(),
            child: SizedBox(
              width: cardWidth,
              child: _StepCard(index: i, glow: glow, glowOn: false, drop: dropCurve),
            ),
          ),
        ),
      );
}

class _StepCard extends StatelessWidget {
  final int index;
  final bool glowOn;
  final Animation<double> glow;
  final Animation<double>? drop; // set for the open (dropped-down) copy
  const _StepCard({required this.index, required this.glow, required this.glowOn, this.drop});

  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    final (title, icon, text) = steps[index];
    final open = drop != null;
    final head = SizedBox(
      height: _cardHeight,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(22, 20, 20, 20),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Container(
              width: 58,
              height: 58,
              decoration: BoxDecoration(
                color: s.primary.withValues(alpha: open ? 0.18 : 0.09),
                borderRadius: BorderRadius.circular(16),
              ),
              child: Icon(icon, color: s.primary, size: 34),
            ),
            const Spacer(),
            Text('[ 0${index + 1} ]', style: TextStyle(color: s.onSurfaceVariant, fontSize: 11, letterSpacing: 2)),
            const SizedBox(width: 10),
            Icon(open ? Icons.expand_less_rounded : Icons.expand_more_rounded,
                size: 20, color: open ? s.primary : s.onSurfaceVariant),
          ]),
          const Spacer(),
          Text(title,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: Theme.of(context).textTheme.titleLarge?.copyWith(fontSize: 21)),
        ]),
      ),
    );
    final Widget body = !open
        ? head
        : Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            head,
            // the drop-down part: grows from nothing, the text fades and lifts in
            ClipRect(
              child: AnimatedBuilder(
                animation: drop!,
                builder: (context, child) {
                  final v = drop!.value.clamp(0.0, 1.0);
                  return Align(
                    alignment: Alignment.topCenter,
                    heightFactor: v,
                    child: Opacity(
                      opacity: const Interval(0.35, 1).transform(v),
                      child: Transform.translate(offset: Offset(0, 12 * (1 - v)), child: child),
                    ),
                  );
                },
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(22, 0, 22, 22),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Divider(color: s.primary.withValues(alpha: 0.18)),
                    const SizedBox(height: 10),
                    Text(text, style: TextStyle(color: s.onSurfaceVariant, height: 1.55, fontSize: 13.5)),
                  ]),
                ),
              ),
            ),
          ]);
    return AnimatedBuilder(
      animation: glow,
      child: body,
      builder: (context, child) {
        // a soft bump that travels across the five cards
        final pos = glow.value * steps.length;
        final d = (pos - index - 0.5).abs();
        final lit = glowOn ? math.max(0.0, 1 - d * 1.4) : 0.0;
        final edge = open ? 1.0 : lit;
        return Material(
          type: MaterialType.transparency,
          child: Container(
            clipBehavior: Clip.antiAlias,
            decoration: BoxDecoration(
              color: open ? s.surfaceContainer : s.surfaceContainerLow,
              borderRadius: BorderRadius.circular(22),
              border: Border.all(color: Color.lerp(s.outlineVariant, s.primary.withValues(alpha: 0.55), edge)!),
              boxShadow: [
                if (open) BoxShadow(color: Colors.black.withValues(alpha: 0.55), blurRadius: 30, offset: const Offset(0, 14)),
                if (edge > 0.02) BoxShadow(color: s.primary.withValues(alpha: 0.14 * edge), blurRadius: 28, spreadRadius: -4),
              ],
            ),
            child: child,
          ),
        );
      },
    );
  }
}
