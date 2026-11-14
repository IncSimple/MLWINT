// MLWINT Flutter window: modern scrolling. Save as MLWINT/mlwint_app/lib/smooth.dart
//   SmoothScrollController - eased mouse-wheel scrolling (the "Lenis" feel): every wheel notch moves a target and the
//                            page glides toward it with an exponential ease, so motion never jumps or stutters.
//                            Touchpads and dragging keep their native feel.
//   SmoothScroll           - owns a SmoothScrollController and adds the modern scroll aids instead of a scrollbar:
//                            a slim floating pill that only appears while you scroll (or hover the right edge) and can
//                            be dragged to fly through long pages, plus a "back to top" button.
//   Reveal                 - plays a blur-to-clear rise when a section scrolls into view (like GSAP ScrollTrigger).
//   NoScrollbars           - the app-wide scroll behaviour: no classic scrollbars anywhere.
import 'dart:async';
import 'dart:math' as math;
import 'dart:ui' as ui;

import 'package:material_ui/material_ui.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/scheduler.dart';

import 'theme.dart';

/// How far one wheel notch travels (Windows sends ~60 px; web pages move ~100).
const wheelMultiplier = 1.7;

/// How quickly the page settles on its target (higher = snappier). 9 feels like Lenis' default.
const glide = 9.0;

/// Turned off by the Animations setting: then the wheel scrolls instantly like before.
bool smoothScrolling = true;

// ---------------------------------------------------------------------------------------------- controller
class SmoothScrollController extends ScrollController {
  SmoothScrollController({super.initialScrollOffset});

  @override
  ScrollPosition createScrollPosition(ScrollPhysics physics, ScrollContext context, ScrollPosition? oldPosition) =>
      _SmoothPosition(
        physics: physics,
        context: context,
        oldPosition: oldPosition,
        initialPixels: initialScrollOffset,
        keepScrollOffset: keepScrollOffset,
        debugLabel: debugLabel,
      );
}

class _SmoothPosition extends ScrollPositionWithSingleContext {
  _SmoothPosition({
    required super.physics,
    required super.context,
    super.oldPosition,
    super.initialPixels,
    super.keepScrollOffset,
    super.debugLabel,
  });

  @override
  void pointerScroll(double delta) {
    if (!smoothScrolling || delta == 0.0) {
      super.pointerScroll(delta);
      return;
    }
    final current = activity;
    final from = current is _GlideActivity ? current.target : pixels;
    final target = (from + delta * wheelMultiplier).clamp(minScrollExtent, maxScrollExtent);
    if (target == from) return;
    updateUserScrollDirection(delta > 0 ? ScrollDirection.reverse : ScrollDirection.forward);
    if (current is _GlideActivity) {
      current.target = target; // keep gliding, just further: no restart, no jolt
    } else {
      beginActivity(_GlideActivity(this, target: target, vsync: context.vsync));
    }
  }
}

/// Moves the position toward [target] every frame: next = now + (target - now) * (1 - e^(-glide * dt)).
class _GlideActivity extends ScrollActivity {
  _GlideActivity(super.delegate, {required this.target, required TickerProvider vsync}) {
    _ticker = vsync.createTicker(_tick)..start();
  }

  double target;
  late final Ticker _ticker;
  Duration _last = Duration.zero;
  double _velocity = 0;

  ScrollPosition get _position => delegate as ScrollPosition;

  void _tick(Duration now) {
    final dt = ((now - _last).inMicroseconds / 1e6).clamp(1 / 240, 1 / 20);
    _last = now;
    final p = _position;
    target = target.clamp(p.minScrollExtent, p.maxScrollExtent);
    final current = p.pixels;
    var next = current + (target - current) * (1 - math.exp(-glide * dt));
    if ((target - next).abs() < 0.4) next = target;
    _velocity = (next - current) / dt;
    final overscroll = delegate.setPixels(next);
    if (next == target || overscroll.abs() > 1e-6) {
      _velocity = 0;
      delegate.goIdle(); // disposes this activity
    }
  }

  @override
  bool get shouldIgnorePointer => false; // buttons stay clickable while the page glides

  @override
  bool get isScrolling => true;

  @override
  double get velocity => _velocity;

  @override
  void dispose() {
    _ticker.dispose();
    super.dispose();
  }
}

// ---------------------------------------------------------------------------------------------- no scrollbars
class NoScrollbars extends MaterialScrollBehavior {
  const NoScrollbars();

  @override
  Widget buildScrollbar(BuildContext context, Widget child, ScrollableDetails details) => child;

  @override
  Widget buildOverscrollIndicator(BuildContext context, Widget child, ScrollableDetails details) => child;
}

// ---------------------------------------------------------------------------------------------- scroll aids
/// A smooth-scrolling area with the floating scroll pill and a back-to-top button.
/// ```dart
/// SmoothScroll(builder: (context, controller) => ListView(controller: controller, children: [...]))
/// ```
class SmoothScroll extends StatefulWidget {
  final Widget Function(BuildContext context, ScrollController controller) builder;
  final bool backToTop;
  final double pillInset;
  const SmoothScroll({super.key, required this.builder, this.backToTop = true, this.pillInset = 4});
  @override
  State<SmoothScroll> createState() => _SmoothScrollState();
}

class _SmoothScrollState extends State<SmoothScroll> {
  final controller = SmoothScrollController();

  @override
  void dispose() {
    controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Stack(children: [
        Positioned.fill(child: widget.builder(context, controller)),
        Positioned(
          top: 6,
          bottom: 6,
          right: widget.pillInset,
          width: 16,
          child: _ScrollPill(controller: controller),
        ),
        if (widget.backToTop)
          Positioned(right: 28, bottom: 24, child: _BackToTop(controller: controller)),
      ]);
}

/// The slim pill: hidden at rest, fades in while scrolling or when the pointer is near the right edge; drag it to
/// fly through the page. While dragging it shows how far down you are.
class _ScrollPill extends StatefulWidget {
  final ScrollController controller;
  const _ScrollPill({required this.controller});
  @override
  State<_ScrollPill> createState() => _ScrollPillState();
}

class _ScrollPillState extends State<_ScrollPill> {
  bool hover = false, dragging = false, scrolling = false;
  Timer? _hide;
  ScrollPosition? _watched;

  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_onScroll);
  }

  @override
  void dispose() {
    _hide?.cancel();
    widget.controller.removeListener(_onScroll);
    _watched?.isScrollingNotifier.removeListener(_onScroll);
    super.dispose();
  }

  void _onScroll() {
    if (!mounted) return;
    final pos = widget.controller.hasClients ? widget.controller.position : null;
    if (pos != _watched) {
      _watched?.isScrollingNotifier.removeListener(_onScroll);
      _watched = pos?..isScrollingNotifier.addListener(_onScroll);
    }
    _hide?.cancel();
    setState(() => scrolling = true);
    _hide = Timer(const Duration(milliseconds: 900), () {
      if (mounted) setState(() => scrolling = false);
    });
  }

  @override
  Widget build(BuildContext context) {
    final s = Theme.of(context).colorScheme;
    final c = widget.controller;
    if (!c.hasClients || !c.position.hasContentDimensions || c.position.maxScrollExtent <= 0) {
      // nothing to scroll yet: check again after layout
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted && c.hasClients && c.position.hasContentDimensions && c.position.maxScrollExtent > 0) {
          setState(() {});
        }
      });
      return const SizedBox.shrink();
    }
    final p = c.position;
    return LayoutBuilder(builder: (context, box) {
      final track = box.maxHeight;
      final fraction = (p.viewportDimension / (p.maxScrollExtent + p.viewportDimension)).clamp(0.06, 1.0);
      final pill = math.max(44.0, track * fraction);
      final progress = (p.pixels / p.maxScrollExtent).clamp(0.0, 1.0);
      final top = (track - pill) * progress;
      final visible = scrolling || hover || dragging;
      final wide = hover || dragging;
      void jump(double dy) {
        final f = ((dy - pill / 2) / (track - pill)).clamp(0.0, 1.0);
        c.jumpTo(f * p.maxScrollExtent);
      }

      return MouseRegion(
        onEnter: (_) => setState(() => hover = true),
        onExit: (_) => setState(() => hover = false),
        cursor: SystemMouseCursors.grab,
        child: GestureDetector(
          behavior: HitTestBehavior.translucent,
          onVerticalDragStart: (d) {
            setState(() => dragging = true);
            jump(d.localPosition.dy);
          },
          onVerticalDragUpdate: (d) => jump(d.localPosition.dy),
          onVerticalDragEnd: (_) => setState(() => dragging = false),
          onTapDown: visible
              ? (d) => c.animateTo(
                  ((d.localPosition.dy - pill / 2) / (track - pill)).clamp(0.0, 1.0) * p.maxScrollExtent,
                  duration: Motion.long,
                  curve: Motion.enter)
              : null,
          child: AnimatedOpacity(
            opacity: visible ? 1 : 0,
            duration: visible ? Motion.short : Motion.long,
            child: Stack(clipBehavior: Clip.none, children: [
              Positioned(
                top: top,
                right: 3,
                child: AnimatedContainer(
                  duration: Motion.short,
                  curve: Motion.standard,
                  width: wide ? 8 : 4,
                  height: pill,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(8),
                    gradient: LinearGradient(
                      begin: Alignment.topCenter,
                      end: Alignment.bottomCenter,
                      colors: [s.primary.withValues(alpha: wide ? 0.95 : 0.55), s.primary.withValues(alpha: wide ? 0.6 : 0.25)],
                    ),
                    boxShadow: [BoxShadow(color: s.primary.withValues(alpha: wide ? 0.35 : 0.15), blurRadius: 12)],
                  ),
                ),
              ),
              if (dragging)
                Positioned(
                  top: top + pill / 2 - 14,
                  right: 18,
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                    decoration: BoxDecoration(
                        color: s.surfaceContainerHighest, borderRadius: BorderRadius.circular(14),
                        border: Border.all(color: s.primary.withValues(alpha: 0.4))),
                    child: Text('${(progress * 100).round()}%',
                        style: TextStyle(color: s.primary, fontSize: 12, fontWeight: FontWeight.w700)),
                  ),
                ),
            ]),
          ),
        ),
      );
    });
  }
}

/// A round "back to top" button that rises in once you are more than a screen down.
class _BackToTop extends StatelessWidget {
  final ScrollController controller;
  const _BackToTop({required this.controller});
  @override
  Widget build(BuildContext context) => ListenableBuilder(
        listenable: controller,
        builder: (context, _) {
          final show = controller.hasClients &&
              controller.position.hasContentDimensions &&
              controller.position.pixels > controller.position.viewportDimension * 0.9;
          return AnimatedSlide(
            offset: show ? Offset.zero : const Offset(0, 0.6),
            duration: Motion.medium,
            curve: show ? Motion.enter : Motion.exit,
            child: AnimatedOpacity(
              opacity: show ? 1 : 0,
              duration: Motion.medium,
              child: IgnorePointer(
                ignoring: !show,
                child: FloatingActionButton.small(
                  heroTag: null,
                  tooltip: 'Back to top',
                  elevation: 2,
                  onPressed: () => controller.animateTo(0,
                      duration: Duration(milliseconds: (controller.offset / 4).clamp(450, 1100).round()),
                      curve: Easing.emphasizedDecelerate),
                  child: const Icon(Icons.arrow_upward_rounded),
                ),
              ),
            ),
          );
        },
      );
}

// ---------------------------------------------------------------------------------------------- reveal on scroll
/// Blur-to-clear rise, played once when this widget scrolls into view (or at once if it starts visible).
class Reveal extends StatefulWidget {
  final Widget child;
  final Duration delay;
  final double dy, blur;
  const Reveal({super.key, required this.child, this.delay = Duration.zero, this.dy = 34, this.blur = 10});
  @override
  State<Reveal> createState() => _RevealState();
}

class _RevealState extends State<Reveal> with SingleTickerProviderStateMixin {
  late final c = AnimationController(vsync: this, duration: const Duration(milliseconds: 850));
  late final a = CurvedAnimation(parent: c, curve: Easing.emphasizedDecelerate);
  ScrollPosition? _pos;
  bool _started = false;

  @override
  void initState() {
    super.initState();
    if (!smoothScrolling) {
      c.value = 1; // animations off: show at once
      _started = true;
    }
    WidgetsBinding.instance.addPostFrameCallback((_) => _check());
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final pos = Scrollable.maybeOf(context)?.position;
    if (pos != _pos) {
      _pos?.removeListener(_check);
      _pos = pos?..addListener(_check);
    }
  }

  void _check() {
    if (_started || !mounted) return;
    final box = context.findRenderObject() as RenderBox?;
    final scrollable = Scrollable.maybeOf(context);
    final view = scrollable?.context.findRenderObject() as RenderBox?;
    if (box == null || !box.attached || !box.hasSize) return;
    var visible = true;
    if (view != null && view.attached && view.hasSize) {
      final top = box.localToGlobal(Offset.zero, ancestor: view).dy;
      visible = top < view.size.height - 40 && top + box.size.height > 0;
    }
    if (visible) {
      _started = true;
      _pos?.removeListener(_check);
      Future.delayed(widget.delay, () {
        if (mounted) c.forward();
      });
    }
  }

  @override
  void dispose() {
    _pos?.removeListener(_check);
    c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
        animation: a,
        child: widget.child,
        builder: (context, child) {
          final v = a.value;
          if (v >= 1) return child!;
          final sigma = widget.blur * (1 - v);
          Widget w = Transform.translate(offset: Offset(0, widget.dy * (1 - v)), child: child);
          if (sigma > 0.05) {
            w = ImageFiltered(imageFilter: ui.ImageFilter.blur(sigmaX: sigma, sigmaY: sigma), child: w);
          }
          return Opacity(opacity: v.clamp(0.0, 1.0), child: w);
        },
      );
}
