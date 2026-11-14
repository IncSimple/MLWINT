// MLWINT Flutter window: the Material 3 theme and the small building blocks every page uses.
// Save as MLWINT/mlwint_app/lib/theme.dart
// Material 3: colours come from ONE seed (MLWINT's neon lime) through the M3 colour system; surfaces use the tonal
// surfaceContainer levels instead of shadows; shapes follow the M3 corner scale; motion uses the M3 emphasized
// easing and duration tokens.
import 'dart:ui' as ui;

import 'package:material_ui/material_ui.dart';

import 'state.dart';

const seed = Color(0xFF7CF05A);
const display = 'Segoe UI Variable Display';
const body = 'Segoe UI Variable Text';

/// M3 motion tokens used across the app.
abstract final class Motion {
  static const enter = Easing.emphasizedDecelerate;
  static const exit = Easing.emphasizedAccelerate;
  static const standard = Easing.standard;
  static const short = Durations.short4; // 200 ms
  static const medium = Durations.medium2; // 300 ms
  static const long = Durations.long2; // 500 ms
  static const extraLong = Durations.extralong2; // 900 ms
}

ThemeData buildTheme() {
  var scheme = ColorScheme.fromSeed(
    seedColor: seed,
    brightness: Brightness.dark,
    dynamicSchemeVariant: DynamicSchemeVariant.fidelity, // keeps primary close to the lime seed
  );
  // a deeper, near-black tonal ramp (same green hue) for MLWINT's look
  scheme = scheme.copyWith(
    primary: seed,
    onPrimary: const Color(0xFF061005),
    surface: const Color(0xFF070A07),
    surfaceContainerLowest: const Color(0xFF050705),
    surfaceContainerLow: const Color(0xFF0C110C),
    surfaceContainer: const Color(0xFF101610),
    surfaceContainerHigh: const Color(0xFF151D15),
    surfaceContainerHighest: const Color(0xFF1B251B),
    onSurface: const Color(0xFFE9F2E9),
    onSurfaceVariant: const Color(0xFF9DAE9D),
    outline: const Color(0xFF3A4A3A),
    outlineVariant: const Color(0xFF1F2B1F),
  );
  final base = ThemeData(useMaterial3: true, colorScheme: scheme, fontFamily: body, brightness: Brightness.dark);
  final t = base.textTheme;
  TextStyle? disp(TextStyle? s, {FontWeight w = FontWeight.w300}) =>
      s?.copyWith(fontFamily: display, fontWeight: w, letterSpacing: -0.5);
  return base.copyWith(
    scaffoldBackgroundColor: scheme.surface,
    textTheme: t.copyWith(
      displayLarge: disp(t.displayLarge),
      displayMedium: disp(t.displayMedium),
      displaySmall: disp(t.displaySmall),
      headlineLarge: disp(t.headlineLarge),
      headlineMedium: disp(t.headlineMedium),
      headlineSmall: disp(t.headlineSmall, w: FontWeight.w400),
      titleLarge: disp(t.titleLarge, w: FontWeight.w400),
    ),
    cardTheme: CardThemeData(
      elevation: 0,
      margin: EdgeInsets.zero,
      color: scheme.surfaceContainerLow,
      shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(20), side: BorderSide(color: scheme.outlineVariant)),
    ),
    navigationRailTheme: NavigationRailThemeData(
      backgroundColor: scheme.surfaceContainerLowest,
      indicatorColor: scheme.primary.withValues(alpha: 0.16),
      selectedIconTheme: IconThemeData(color: scheme.primary),
      selectedLabelTextStyle: TextStyle(color: scheme.primary, fontWeight: FontWeight.w600),
      unselectedLabelTextStyle: TextStyle(color: scheme.onSurfaceVariant),
    ),
    filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
            minimumSize: const Size(0, 48),
            padding: const EdgeInsets.symmetric(horizontal: 24),
            textStyle: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14))),
    outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
            minimumSize: const Size(0, 44),
            padding: const EdgeInsets.symmetric(horizontal: 20),
            side: BorderSide(color: scheme.outline))),
    chipTheme: ChipThemeData(
      side: BorderSide(color: scheme.outlineVariant),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: scheme.surfaceContainer,
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(14), borderSide: BorderSide.none),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
    ),
    dividerTheme: DividerThemeData(color: scheme.outlineVariant, space: 1, thickness: 1),
    tooltipTheme: TooltipThemeData(
      waitDuration: const Duration(milliseconds: 500),
      decoration: BoxDecoration(color: scheme.surfaceContainerHighest, borderRadius: BorderRadius.circular(8)),
      textStyle: TextStyle(color: scheme.onSurface, fontSize: 12),
    ),
    snackBarTheme: const SnackBarThemeData(behavior: SnackBarBehavior.floating, width: 560),
    pageTransitionsTheme: const PageTransitionsTheme(
        builders: {TargetPlatform.windows: FadeForwardsPageTransitionsBuilder()}),
    scrollbarTheme: ScrollbarThemeData(
      thumbColor: WidgetStatePropertyAll(scheme.onSurfaceVariant.withValues(alpha: 0.35)),
      radius: const Radius.circular(8),
      thickness: const WidgetStatePropertyAll(6),
    ),
  );
}

// ---------------------------------------------------------------------------------------------- building blocks
/// "[ PROTECTION STATUS ]" style label above a heading.
class Tag extends StatelessWidget {
  final String text;
  final Color? colour;
  const Tag(this.text, {super.key, this.colour});
  @override
  Widget build(BuildContext context) => Text('[ ${text.toUpperCase()} ]',
      style: TextStyle(
          color: colour ?? Theme.of(context).colorScheme.primary,
          fontSize: 11,
          letterSpacing: 2.2,
          fontWeight: FontWeight.w600));
}

/// A tonal card with an optional tag + title, the main container of every page.
class Section extends StatelessWidget {
  final String? tag, title;
  final Widget child;
  final Widget? trailing;
  final EdgeInsets padding;
  const Section({super.key, this.tag, this.title, this.trailing, required this.child,
      this.padding = const EdgeInsets.all(24)});
  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Card(
      child: Padding(
        padding: padding,
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, mainAxisSize: MainAxisSize.min, children: [
          if (tag != null || title != null || trailing != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 16),
              child: Row(crossAxisAlignment: CrossAxisAlignment.end, children: [
                Expanded(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    if (tag != null) Tag(tag!),
                    if (tag != null && title != null) const SizedBox(height: 6),
                    if (title != null) Text(title!, style: t.titleLarge),
                  ]),
                ),
                ?trailing,
              ]),
            ),
          child,
        ]),
      ),
    );
  }
}

/// The level as a small tonal pill: "● Be careful".
class LevelChip extends StatelessWidget {
  final String level;
  final bool words;
  const LevelChip(this.level, {super.key, this.words = true});
  @override
  Widget build(BuildContext context) {
    final c = colourOf(level);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(color: c.withValues(alpha: 0.14), borderRadius: BorderRadius.circular(20)),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Container(width: 7, height: 7, decoration: BoxDecoration(color: c, shape: BoxShape.circle)),
        const SizedBox(width: 6),
        Text(words ? (levelWords[level] ?? level) : level,
            style: TextStyle(color: c, fontSize: 12, fontWeight: FontWeight.w600)),
      ]),
    );
  }
}

/// The score in a rounded square tinted with its level.
class ScoreBadge extends StatelessWidget {
  final Json r;
  final double size;
  const ScoreBadge(this.r, {super.key, this.size = 44});
  @override
  Widget build(BuildContext context) {
    final ok = r.assessed;
    final c = ok ? colourOf(r.level) : Theme.of(context).colorScheme.onSurfaceVariant;
    return Container(
      width: size,
      height: size,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: c.withValues(alpha: ok ? 0.13 : 0.06),
        borderRadius: BorderRadius.circular(size * 0.3),
        border: Border.all(color: c.withValues(alpha: 0.35)),
      ),
      child: ok
          ? Text('${r.score}',
              style: TextStyle(fontFamily: display, color: c, fontSize: size * 0.4, fontWeight: FontWeight.w400))
          : Icon(Icons.remove, color: c, size: size * 0.4),
    );
  }
}

/// A number that counts up to its value (M3 emphasized decelerate).
class CountUp extends StatelessWidget {
  final num value;
  final TextStyle? style;
  final bool animate;
  final String suffix;
  const CountUp(this.value, {super.key, this.style, this.animate = true, this.suffix = ''});
  @override
  Widget build(BuildContext context) {
    if (!animate) return Text('${value.round()}$suffix', style: style);
    return TweenAnimationBuilder<double>(
      tween: Tween(begin: 0, end: value.toDouble()),
      duration: Motion.extraLong,
      curve: Motion.enter,
      builder: (_, v, _) => Text('${v.round()}$suffix', style: style),
    );
  }
}

/// Slides + fades its child in once (M3 enter motion), optionally from a blur. [delay] staggers a group.
class Appear extends StatefulWidget {
  final Widget child;
  final Duration delay;
  final double dy, blur;
  const Appear({super.key, required this.child, this.delay = Duration.zero, this.dy = 18, this.blur = 0});
  @override
  State<Appear> createState() => _AppearState();
}

class _AppearState extends State<Appear> with SingleTickerProviderStateMixin {
  late final c = AnimationController(vsync: this, duration: Motion.long);
  late final a = CurvedAnimation(parent: c, curve: Motion.enter);
  @override
  void initState() {
    super.initState();
    Future.delayed(widget.delay, () {
      if (mounted) c.forward();
    });
  }

  @override
  void dispose() {
    c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
        animation: a,
        builder: (_, child) {
          final v = a.value;
          if (v >= 1) return child!;
          Widget w = Transform.translate(offset: Offset(0, widget.dy * (1 - v)), child: child);
          final sigma = widget.blur * (1 - v);
          if (sigma > 0.05) w = ImageFiltered(imageFilter: ui.ImageFilter.blur(sigmaX: sigma, sigmaY: sigma), child: w);
          return Opacity(opacity: v.clamp(0.0, 1.0), child: w);
        },
        child: widget.child,
      );
}

/// Two-tone headline: first part bright, second part soft. Words rise in one after another.
class Headline extends StatelessWidget {
  final String first, second;
  final double size;
  final bool animate;
  const Headline(this.first, this.second, {super.key, this.size = 44, this.animate = true});
  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    final words = [
      for (final w in first.split(' ')) (w, s.onSurface),
      for (final w in second.split(' ')) (w, s.onSurfaceVariant.withValues(alpha: 0.75)),
    ];
    final style = TextStyle(fontFamily: display, fontSize: size, fontWeight: FontWeight.w300, height: 1.12,
        letterSpacing: -size * 0.02);
    return Wrap(
      key: ValueKey('$first|$second'),
      spacing: size * 0.26,
      runSpacing: 2,
      children: [
        for (final (i, (w, c)) in words.indexed)
          animate
              ? Appear(
                  delay: Duration(milliseconds: 70 * i),
                  dy: size * 0.3,
                  blur: size * 0.22, // words go from blurred to sharp, one after another
                  child: Text(w, style: style.copyWith(color: c)))
              : Text(w, style: style.copyWith(color: c)),
      ],
    );
  }
}

void snack(BuildContext context, String text, {bool error = false}) {
  final s = Theme.of(context).colorScheme;
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(
      content: Text(text, style: TextStyle(color: error ? s.onErrorContainer : null)),
      backgroundColor: error ? s.errorContainer : null,
      showCloseIcon: true,
    ));
}

Future<bool> confirm(BuildContext context, String title, String text, {String yes = 'Continue', IconData? icon}) async {
  final ok = await showDialog<bool>(
    context: context,
    builder: (c) => AlertDialog(
      icon: icon == null ? null : Icon(icon),
      title: Text(title),
      content: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 460), child: Text(text)),
      actions: [
        TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(c, true), child: Text(yes)),
      ],
    ),
  );
  return ok == true;
}