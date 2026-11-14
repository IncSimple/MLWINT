// MLWINT Flutter window: the living visuals, drawn on the GPU.
// Save as MLWINT/mlwint_app/lib/orb.dart
//   ThreatOrb  - a 3-D particle sphere showing a score: calm and green when safe, faster, restless and red when not;
//                while scanning a light band sweeps over it and the ring shows the progress
//   StreakField - the hero background: perspective light streaks with travelling pulses and drifting dust
// Both repaint through a ValueNotifier (no widget rebuilds), sit in a RepaintBoundary and stop when hidden.
import 'dart:math' as math;
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:material_ui/material_ui.dart';
import 'package:flutter/scheduler.dart';

import 'state.dart';
import 'theme.dart';

/// Time in seconds, advanced by a Ticker only while the widget is visible and animations are on.
mixin _Clock<T extends StatefulWidget> on State<T>, SingleTickerProviderStateMixin<T> {
  final time = ValueNotifier<double>(0);
  late final Ticker _ticker = createTicker((e) {
    time.value = e.inMicroseconds / 1e6 + _base;
    onTick();
  });
  double _base = 0;
  bool get animate;
  void onTick() {}

  void syncClock() {
    if (animate && !_ticker.isActive) {
      _base = time.value;
      _ticker.start();
    } else if (!animate && _ticker.isActive) {
      _ticker.stop();
    }
  }

  @override
  void dispose() {
    _ticker.dispose();
    time.dispose();
    super.dispose();
  }
}

// ---------------------------------------------------------------------------------------------- threat orb
class ThreatOrb extends StatefulWidget {
  final int? score;
  final String level;
  final bool scanning;
  final int done, total;
  final bool compact;
  final bool animate;
  final String caption;
  const ThreatOrb({super.key, this.score, this.level = '', this.scanning = false, this.done = 0, this.total = 0,
      this.compact = false, this.animate = true, this.caption = ''});
  @override
  State<ThreatOrb> createState() => _ThreatOrbState();
}

class _ThreatOrbState extends State<ThreatOrb> with SingleTickerProviderStateMixin, _Clock {
  late final Float32List unit = _fibonacci(widget.compact ? 560 : 1100);
  double shown = 0; // the score on screen, easing toward the real one
  double lastT = 0;
  @override
  bool get animate => widget.animate;

  static Float32List _fibonacci(int n) {
    final out = Float32List(n * 4); // x, y, z, phase
    final golden = math.pi * (3 - math.sqrt(5));
    final rnd = math.Random(7);
    for (var i = 0; i < n; i++) {
      final y = 1 - (i / (n - 1)) * 2;
      final r = math.sqrt(1 - y * y);
      final th = golden * i;
      out[i * 4] = math.cos(th) * r;
      out[i * 4 + 1] = y;
      out[i * 4 + 2] = math.sin(th) * r;
      out[i * 4 + 3] = rnd.nextDouble() * math.pi * 2;
    }
    return out;
  }

  double get target => widget.scanning
      ? (widget.total > 0 ? 100 * widget.done / widget.total : 0)
      : (widget.score ?? 0).toDouble();

  @override
  void initState() {
    super.initState();
    if (!widget.animate) shown = target;
    syncClock();
  }

  @override
  void didUpdateWidget(ThreatOrb old) {
    super.didUpdateWidget(old);
    if (!widget.animate) {
      shown = target;
      time.value += 0.0001; // repaint once
    }
    syncClock();
  }

  @override
  void onTick() {
    final dt = (time.value - lastT).clamp(0.0, 0.1);
    lastT = time.value;
    shown += (target - shown) * math.min(1.0, dt * 3.2);
  }

  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    final has = widget.score != null || widget.scanning;
    final colour = widget.scanning ? s.primary : (widget.score == null ? s.primary : colourOf(widget.level));
    return RepaintBoundary(
      child: CustomPaint(
        painter: _OrbPainter(this, colour, s, has),
        child: const SizedBox.expand(),
      ),
    );
  }
}

class _OrbPainter extends CustomPainter {
  final _ThreatOrbState o;
  final Color colour;
  final ColorScheme s;
  final bool has;
  _OrbPainter(this.o, this.colour, this.s, this.has) : super(repaint: o.time);

  static const _layers = 5;

  @override
  void paint(Canvas canvas, Size size) {
    final w = o.widget;
    final t = o.time.value;
    final level = w.scanning ? 'GUARDED' : (w.score == null ? 'LOW' : w.level);
    final rank = (levelRank[level] ?? 0).toDouble();
    final c = Offset(size.width / 2, size.height / 2 - (w.compact ? 4 : 14));
    final ringR = math.min(size.width, size.height - (w.compact ? 16 : 52)) / 2 - 6;
    final R = ringR * 0.74;

    // glow
    canvas.drawCircle(
        c,
        ringR * 1.25,
        Paint()
          ..shader = ui.Gradient.radial(c, ringR * 1.25,
              [colour.withValues(alpha: has ? 0.20 : 0.10), colour.withValues(alpha: 0.0)], [0.0, 1.0]));

    // sphere
    final speed = 0.18 + rank * 0.16 + (w.scanning ? 0.5 : 0);
    final wobble = 0.012 + rank * 0.018;
    final jitter = rank >= 3 ? (rank - 2) * 0.006 : 0.0;
    final a = t * speed, tilt = 0.42 + 0.06 * math.sin(t * 0.3);
    final ca = math.cos(a), sa = math.sin(a), ct = math.cos(tilt), st = math.sin(tilt);
    final scanY = math.sin(t * 1.6); // the scanning light band, -1..1
    final n = o.unit.length ~/ 4;
    final buckets = List.generate(_layers + 1, (_) => Float32List(n * 2));
    final counts = List.filled(_layers + 1, 0);
    for (var i = 0; i < n; i++) {
      var x = o.unit[i * 4], y = o.unit[i * 4 + 1], z = o.unit[i * 4 + 2];
      final ph = o.unit[i * 4 + 3];
      final k = 1 + wobble * math.sin(3 * y + t * (1.2 + rank * 0.5) + ph) + jitter * math.sin(t * 23 + ph * 7);
      x *= k;
      y *= k;
      z *= k;
      final x1 = x * ca + z * sa, z1 = -x * sa + z * ca; // spin around y
      final y2 = y * ct - z1 * st, z2 = y * st + z1 * ct; // tilt toward the viewer
      var layer = ((z2 + 1.1) / 2.2 * _layers).floor().clamp(0, _layers - 1);
      if (w.scanning && (y2 - scanY).abs() < 0.07) layer = _layers; // in the light band
      final j = counts[layer]++;
      buckets[layer][j * 2] = c.dx + x1 * R;
      buckets[layer][j * 2 + 1] = c.dy + y2 * R;
    }
    for (var l = 0; l <= _layers; l++) {
      if (counts[l] == 0) continue;
      final band = l == _layers;
      final depth = band ? 1.0 : l / (_layers - 1);
      final p = Paint()
        ..color = (band ? Colors.white : colour).withValues(alpha: band ? 0.95 : (has ? 0.10 + depth * 0.80 : 0.08 + depth * 0.40))
        ..strokeWidth = (w.compact ? 0.9 : 1.1) + depth * (w.compact ? 1.4 : 2.0)
        ..strokeCap = StrokeCap.round;
      canvas.drawRawPoints(ui.PointMode.points, Float32List.sublistView(buckets[l], 0, counts[l] * 2), p);
    }

    // ring: track, ticks, value arc
    final rect = Rect.fromCircle(center: c, radius: ringR);
    canvas.drawCircle(c, ringR, Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2
      ..color = s.outlineVariant);
    final ticks = Paint()
      ..color = s.onSurfaceVariant.withValues(alpha: 0.25)
      ..strokeWidth = 1;
    for (var i = 0; i < 60; i++) {
      final ang = i / 60 * math.pi * 2;
      final r1 = ringR + 6, r2 = ringR + (i % 5 == 0 ? 11 : 8);
      canvas.drawLine(c + Offset(math.cos(ang) * r1, math.sin(ang) * r1),
          c + Offset(math.cos(ang) * r2, math.sin(ang) * r2), ticks);
    }
    final frac = (o.shown / 100).clamp(0.0, 1.0);
    if (has && frac > 0.002) {
      final sweep = math.pi * 2 * frac;
      canvas.drawArc(
          rect,
          -math.pi / 2,
          sweep,
          false,
          Paint()
            ..style = PaintingStyle.stroke
            ..strokeWidth = w.compact ? 4 : 5
            ..strokeCap = StrokeCap.round
            ..shader = SweepGradient(
              startAngle: 0,
              endAngle: math.pi * 2,
              colors: [colour.withValues(alpha: 0.25), colour],
              stops: [0, frac],
              transform: const GradientRotation(-math.pi / 2),
            ).createShader(rect));
      final end = -math.pi / 2 + sweep;
      final tip = c + Offset(math.cos(end) * ringR, math.sin(end) * ringR);
      canvas.drawCircle(tip, w.compact ? 4 : 5.5, Paint()..color = colour);
      canvas.drawCircle(tip, w.compact ? 9 : 13, Paint()..color = colour.withValues(alpha: 0.18));
    }
    if (w.scanning) {
      // a comet that orbits while files are checked
      final ang = t * 2.4;
      canvas.drawArc(rect.inflate(16), ang, 0.6, false, Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 2
        ..strokeCap = StrokeCap.round
        ..shader = SweepGradient(
                colors: [colour.withValues(alpha: 0), colour],
                stops: const [0, 1],
                startAngle: 0,
                endAngle: 0.6,
                transform: GradientRotation(ang))
            .createShader(rect.inflate(16)));
    }

    // the number, on a soft dark halo so the particles never cross it
    canvas.drawCircle(
        c,
        R * 0.62,
        Paint()
          ..shader = ui.Gradient.radial(c, R * 0.62,
              [s.surface.withValues(alpha: 0.92), s.surface.withValues(alpha: 0.0)], [0.45, 1.0]));
    final big = w.scanning
        ? '${w.done}'
        : (w.score == null ? '–' : '${o.shown.round()}');
    _text(canvas, big, c, TextStyle(fontFamily: display, fontSize: R * (w.compact ? 0.62 : 0.56),
        fontWeight: FontWeight.w300, color: s.onSurface, height: 1));
    final small = w.scanning ? 'of ${w.total == 0 ? '…' : w.total}' : (w.score == null ? '' : '/ 100');
    if (small.isNotEmpty) {
      _text(canvas, small, c + Offset(0, R * 0.42), TextStyle(fontSize: R * 0.13, color: s.onSurfaceVariant));
    }
    if (!w.compact) {
      final word = w.scanning
          ? 'CHECKING'
          : (w.score == null ? 'NO SCAN YET' : (levelWords[w.level] ?? w.level).toUpperCase());
      _text(canvas, word, Offset(c.dx, size.height - 30),
          TextStyle(fontSize: 13, letterSpacing: 3, fontWeight: FontWeight.w700, color: colour));
      if (w.caption.isNotEmpty) {
        _text(canvas, w.caption, Offset(c.dx, size.height - 10),
            TextStyle(fontSize: 11.5, color: s.onSurfaceVariant));
      }
    }
  }

  void _text(Canvas canvas, String text, Offset centre, TextStyle style) {
    final tp = TextPainter(text: TextSpan(text: text, style: style), textDirection: TextDirection.ltr)..layout();
    tp.paint(canvas, centre - Offset(tp.width / 2, tp.height / 2));
  }

  @override
  bool shouldRepaint(_OrbPainter old) => true;
}

// ---------------------------------------------------------------------------------------------- hero streaks
class StreakField extends StatefulWidget {
  final Color glow;
  final bool animate;
  final Widget child;
  const StreakField({super.key, required this.glow, required this.child, this.animate = true});
  @override
  State<StreakField> createState() => _StreakFieldState();
}

class _StreakFieldState extends State<StreakField> with SingleTickerProviderStateMixin, _Clock {
  @override
  bool get animate => widget.animate;
  @override
  void initState() {
    super.initState();
    syncClock();
  }

  @override
  void didUpdateWidget(StreakField old) {
    super.didUpdateWidget(old);
    syncClock();
  }

  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    return ClipRRect(
      borderRadius: BorderRadius.circular(28),
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: s.surfaceContainerLowest,
          border: Border.all(color: s.outlineVariant),
          borderRadius: BorderRadius.circular(28),
        ),
        child: Stack(children: [
          Positioned.fill(
              child: RepaintBoundary(child: CustomPaint(painter: _StreakPainter(time, widget.glow, s)))),
          widget.child,
        ]),
      ),
    );
  }
}

class _StreakPainter extends CustomPainter {
  final ValueNotifier<double> time;
  final Color glow;
  final ColorScheme s;
  _StreakPainter(this.time, this.glow, this.s) : super(repaint: time);

  static final _rnd = math.Random(11);
  static final _lines = [for (var i = 0; i < 34; i++) (_rnd.nextDouble(), _rnd.nextDouble(), _rnd.nextDouble())];
  static final _dust = [for (var i = 0; i < 70; i++) (_rnd.nextDouble(), _rnd.nextDouble(), _rnd.nextDouble())];

  @override
  void paint(Canvas canvas, Size size) {
    final t = time.value;
    final vp = Offset(size.width * 0.70, size.height * 0.48); // vanishing point behind the orb
    canvas.drawRect(
        Offset.zero & size,
        Paint()
          ..shader = ui.Gradient.radial(vp, size.width * 0.55,
              [glow.withValues(alpha: 0.16), glow.withValues(alpha: 0.03), Colors.transparent], [0, 0.5, 1]));
    final reach = size.width * 0.95;
    final line = Paint()..strokeWidth = 1;
    final pulse = Paint()
      ..strokeWidth = 1.6
      ..strokeCap = StrokeCap.round;
    for (final (a, b, c) in _lines) {
      final ang = math.pi * 2 * a;
      final dir = Offset(math.cos(ang), math.sin(ang) * 0.55);
      final start = vp + dir * 40;
      final end = vp + dir * reach;
      line.shader = ui.Gradient.linear(start, end, [glow.withValues(alpha: 0.0), glow.withValues(alpha: 0.07 + 0.05 * b)]);
      canvas.drawLine(start, end, line);
      // a pulse travels outward, speeding up like it comes toward you
      final p = ((t * (0.08 + 0.10 * c)) + b) % 1.0;
      final e = p * p;
      final head = vp + dir * (40 + e * reach);
      final tail = vp + dir * (40 + math.max(0, e - 0.06 * (0.3 + p)) * reach);
      pulse.color = glow.withValues(alpha: (0.15 + 0.55 * p) * (1 - p));
      canvas.drawLine(tail, head, pulse);
    }
    final dust = Paint();
    for (final (x, y, z) in _dust) {
      final dx = (x * size.width + t * (6 + z * 14)) % size.width;
      final dy = y * size.height + math.sin(t * 0.5 + x * 9) * 6;
      dust.color = s.onSurface.withValues(alpha: 0.05 + z * 0.12);
      canvas.drawCircle(Offset(dx, dy), 0.6 + z * 1.1, dust);
    }
  }

  @override
  bool shouldRepaint(_StreakPainter old) => old.glow != glow;
}