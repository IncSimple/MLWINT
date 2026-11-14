"""MLWINT motion: everything that moves. Save as MLWINT/src/gui/fx.py
  ThreatOrb     - a living 3D particle sphere in the level's colour (calm when safe, restless and red when
                  dangerous), a glowing ring that sweeps to the score, the number counting up; becomes a scanner
                  (rotating beam + progress ring) during a scan. Replaces the old speedometer.
  StreakPanel   - a glass hero panel with perspective light streaks, travelling light pulses and floating dust
  RevealTitle   - a big two-tone headline that appears word by word (slide up out of a blur), with a dotted icon
  DotIcon       - a dotted pixel icon whose bright dots twinkle
  FloatingTile  - a glass tile that floats gently (one can glow green)
  count_up()    - numbers that count up;  fade_in() - pages that slide and fade in
Animations pause while the window is hidden, and can be switched off in Settings (ANIMATE = False): then every
widget simply shows its final state.
"""
import math, random

from PySide6.QtCore import QEasingCurve, QPointF, QPropertyAnimation, QRectF, QSize, Qt, QTimer, QVariantAnimation
from PySide6.QtGui import (QColor, QFont, QFontMetrics, QLinearGradient, QPainter, QPainterPath, QPen, QPolygonF,
                           QRadialGradient)
from PySide6.QtWidgets import QFrame, QGraphicsOpacityEffect, QSizePolicy, QWidget

from . import theme

ANIMATE = True            # Settings > Animations
FPS = 30


def set_animate(on):
    global ANIMATE
    ANIMATE = bool(on)


class Ticker(QWidget):
    """Base for animated widgets: a frame timer that only runs while the widget is visible and ANIMATE is on."""
    def __init__(self, fps=FPS):
        super().__init__()
        self.t = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(int(1000 / fps))
        self._timer.timeout.connect(self._tick)

    def _tick(self):
        if not ANIMATE or not self.isVisible() or self.window().isMinimized():
            return
        self.t += self._timer.interval() / 1000.0
        self.step()
        self.update()

    def step(self):
        pass

    def showEvent(self, e):
        self._timer.start()
        super().showEvent(e)

    def hideEvent(self, e):
        self._timer.stop()
        super().hideEvent(e)


# ---------------------------------------------------------------------------------------------- threat orb
MOOD = {   # level: (wobble, spin speed, jitter, pulse)
    None: (0.05, 0.25, 0.0, 0.0), 'LOW': (0.05, 0.25, 0.0, 0.0), 'GUARDED': (0.08, 0.35, 0.0, 0.02),
    'ELEVATED': (0.12, 0.5, 0.004, 0.04), 'HIGH': (0.17, 0.75, 0.010, 0.07), 'SEVERE': (0.22, 1.0, 0.018, 0.10)}


class ThreatOrb(Ticker):
    """The score as a living particle sphere + ring. API kept from the old gauge: set_result(score, level), clear(),
    .score, .level; plus set_scanning(done, total) for the scan page.
    compact=True: smaller and fewer particles (detail panel)."""
    def __init__(self, compact=False, caption=''):
        super().__init__()
        self.compact = compact
        self.caption = caption
        self.score, self.level = None, ''
        self.shown = 0.0                      # the number / ring as drawn (eases towards the score)
        self.scanning = None                  # (done, total) while a scan runs
        n = 320 if compact else 720
        golden = math.pi * (3 - math.sqrt(5))
        self.points = []
        for i in range(n):                    # an even spread of dots over a sphere (Fibonacci sphere)
            y = 1 - 2 * (i + 0.5) / n
            r = math.sqrt(1 - y * y)
            a = golden * i
            self.points.append((math.cos(a) * r, y, math.sin(a) * r, random.random() * 6.28))
        self.setMinimumSize(QSize(170, 190) if compact else QSize(300, 300))
        self.anim = QVariantAnimation(self, duration=1400, easingCurve=QEasingCurve.OutCubic)
        self.anim.valueChanged.connect(self._shown)

    def _shown(self, v):
        self.shown = float(v)
        self.update()

    def set_result(self, score, level):
        self.scanning = None
        self.score, self.level = score, level or ''
        target = float(score or 0)
        if ANIMATE:
            self.anim.stop()
            self.anim.setStartValue(0.0)
            self.anim.setEndValue(target)
            self.anim.start()
        else:
            self.shown = target
        self.update()

    def clear(self):
        self.anim.stop()
        self.score, self.level, self.shown, self.scanning = None, '', 0.0, None
        self.update()

    def set_scanning(self, done, total):
        self.scanning = (done, max(total, 1))
        self.update()

    def colour(self):
        if self.scanning:
            return QColor(theme.ACCENT)
        return QColor(theme.LEVEL.get(self.level, theme.ACCENT))

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        text_h = 0 if self.compact else 0
        size = min(w, h - text_h) - (16 if self.compact else 24)
        cx, cy = w / 2, (h - text_h) / 2
        ring_r = size / 2
        orb_r = ring_r * (0.64 if self.compact else 0.62)
        col = self.colour()
        mood = MOOD.get(self.level if not self.scanning else 'GUARDED', MOOD[None])
        wobble, spin, jitter, pulse = mood
        t = self.t
        if self.scanning:
            spin *= 2.2
        breathe = 1 + pulse * math.sin(t * 3.2)

        # glow behind the orb
        g = QRadialGradient(QPointF(cx, cy), orb_r * 1.9)
        c0 = QColor(col)
        c0.setAlpha(60 if self.score is not None or self.scanning else 28)
        c1 = QColor(col)
        c1.setAlpha(0)
        g.setColorAt(0, c0)
        g.setColorAt(1, c1)
        p.setPen(Qt.NoPen)
        p.setBrush(g)
        p.drawEllipse(QPointF(cx, cy), orb_r * 1.9, orb_r * 1.9)

        # particle sphere: rotate, wobble, project, draw in 4 depth layers (far = small and dim)
        ca, sa = math.cos(t * spin), math.sin(t * spin)
        tilt = 0.42
        ct, st = math.cos(tilt), math.sin(tilt)
        layers = [[], [], [], []]
        for x, y, z, ph in self.points:
            k = 1 + wobble * math.sin(3 * x + 2.2 * y + t * 1.6 + ph * 0.15) * breathe
            if jitter:
                k += jitter * math.sin(t * 23 + ph * 7)
            x1, z1 = x * ca + z * sa, -x * sa + z * ca
            y1, z2 = y * ct - z1 * st, y * st + z1 * ct
            persp = 1.0 / (1.9 - z2 * 0.55)
            px = cx + x1 * k * orb_r * persp * 1.25
            py = cy + y1 * k * orb_r * persp * 1.25
            layer = min(3, int((z2 + 1) * 2))
            layers[layer].append(QPointF(px, py))
        sizes = (1.2, 1.7, 2.3, 3.0) if not self.compact else (1.0, 1.4, 1.9, 2.4)
        alphas = (55, 105, 170, 240)
        for i, pts in enumerate(layers):
            c = QColor(col)
            if i == 3:
                c = QColor(col).lighter(125)
            c.setAlpha(alphas[i])
            p.setPen(QPen(c, sizes[i], Qt.SolidLine, Qt.RoundCap))
            p.drawPoints(QPolygonF(pts))

        # ring: faint track with tick dots, the sweep to the score, a bright head
        rect = QRectF(cx - ring_r, cy - ring_r, ring_r * 2, ring_r * 2)
        track = QColor(theme.BORDER_HI)
        p.setPen(QPen(track, 2 if self.compact else 3))
        p.setBrush(Qt.NoBrush)
        p.drawEllipse(rect)
        p.setPen(Qt.NoPen)
        for i in range(40):                                        # tick dots every 2.5 %
            a = math.radians(90 - i * 9)
            c = QColor(theme.MUTED)
            c.setAlpha(70 if i % 4 else 150)
            p.setBrush(c)
            rr = ring_r + (7 if not self.compact else 5)
            p.drawEllipse(QPointF(cx + rr * math.cos(a), cy - rr * math.sin(a)), 1.2, 1.2)
        frac = (self.scanning[0] / self.scanning[1]) if self.scanning else self.shown / 100.0
        if frac > 0:
            grad_pen = QPen(col, 4 if self.compact else 6, Qt.SolidLine, Qt.RoundCap)
            for wdt, alpha in ((14, 30), (8, 60)) if not self.compact else ((9, 30),):
                gc = QColor(col)
                gc.setAlpha(alpha)
                p.setPen(QPen(gc, wdt, Qt.SolidLine, Qt.RoundCap))
                p.drawArc(rect, 90 * 16, -int(360 * 16 * frac))
            p.setPen(grad_pen)
            p.drawArc(rect, 90 * 16, -int(360 * 16 * frac))
            a = math.radians(90 - 360 * frac)
            head = QPointF(cx + ring_r * math.cos(a), cy - ring_r * math.sin(a))
            hg = QRadialGradient(head, 12)
            hc = QColor(col).lighter(140)
            hg.setColorAt(0, hc)
            hc2 = QColor(col)
            hc2.setAlpha(0)
            hg.setColorAt(1, hc2)
            p.setPen(Qt.NoPen)
            p.setBrush(hg)
            p.drawEllipse(head, 12, 12)
        if self.scanning:                                          # the rotating scan beam
            beam = QColor(theme.ACCENT)
            beam.setAlpha(170)
            p.setPen(QPen(beam, 2, Qt.SolidLine, Qt.RoundCap))
            start = int((t * 160) % 360)
            p.drawArc(rect.adjusted(-10, -10, 10, 10), start * 16, 40 * 16)

        # number in the middle (on a soft dark halo so the dots never fight it), words under the sphere
        if self.scanning:
            big, small = f'{self.scanning[0]}', f'of {self.scanning[1]} files'
        elif self.score is None:
            big, small = '-', 'no scan yet' if not self.compact else ''
        else:
            big, small = f'{int(round(self.shown))}', theme.LEVEL_WORDS.get(self.level, '')
        f = theme.display_font(22 if self.compact else 46, QFont.Light)
        fm = QFontMetrics(f)
        halo = QRadialGradient(QPointF(cx, cy), fm.height() * 0.95)
        halo.setColorAt(0, QColor(4, 8, 4, 215))
        halo.setColorAt(0.6, QColor(4, 8, 4, 150))
        halo.setColorAt(1, QColor(4, 8, 4, 0))
        p.setPen(Qt.NoPen)
        p.setBrush(halo)
        p.drawEllipse(QPointF(cx, cy), fm.height() * 0.95, fm.height() * 0.95)
        p.setFont(f)
        p.setPen(QColor(theme.TEXT))
        p.drawText(QRectF(0, cy - fm.height() / 2, w, fm.height()), Qt.AlignCenter, big)
        below = cy + orb_r * 1.08 + (2 if self.compact else 8)
        p.setFont(theme.body_font(8.5 if self.compact else 11, QFont.DemiBold if not self.scanning else QFont.Normal))
        p.setPen(QColor(col if not self.scanning else theme.SOFT))
        p.drawText(QRectF(0, below, w, 24), Qt.AlignHCenter | Qt.AlignTop, small)
        if self.caption and not self.compact and self.score is not None and not self.scanning:
            p.setPen(QColor(theme.MUTED))
            p.setFont(theme.body_font(9))
            p.drawText(QRectF(0, below + 22, w, 20), Qt.AlignHCenter | Qt.AlignTop, self.caption)
        p.end()


# ---------------------------------------------------------------------------------------------- hero panel
class StreakPanel(Ticker):
    """A rounded glass panel with perspective light streaks (pulses travel along them), a soft spotlight from the
    top and floating dust. Put a layout with labels / buttons on it like on any widget."""
    def __init__(self, glow=None):
        super().__init__(fps=30)
        self.glow = QColor(glow or theme.ACCENT)
        self.dust = [(random.random(), random.random(), random.random() * 6.28, 0.6 + random.random() * 1.6)
                     for _ in range(46)]
        self.lines = [(0.30 + i * 0.075, 0.10 + random.random() * 0.25, random.random()) for i in range(7)]
        self.setAttribute(Qt.WA_StyledBackground, False)

    def set_glow(self, colour):
        self.glow = QColor(colour)
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        path = QPainterPath()
        path.addRoundedRect(r, 26, 26)
        p.setClipPath(path)
        bg = QLinearGradient(r.topLeft(), r.bottomLeft())
        bg.setColorAt(0, QColor('#0b140b'))
        bg.setColorAt(1, QColor('#060a06'))
        p.fillPath(path, bg)
        g = QColor(self.glow)
        # spotlight from the top
        spot = QRadialGradient(QPointF(r.center().x() + r.width() * 0.12, r.top() - r.height() * 0.15), r.height() * 1.1)
        s0 = QColor(g)
        s0.setAlpha(46)
        s1 = QColor(g)
        s1.setAlpha(0)
        spot.setColorAt(0, s0)
        spot.setColorAt(1, s1)
        p.fillPath(path, spot)
        # perspective streaks from the left edge towards a vanishing point, with travelling pulses
        vx, vy = r.left() + r.width() * 0.62, r.top() + r.height() * 0.55
        for i, (yf, speed, off) in enumerate(self.lines):
            y0 = r.top() + r.height() * yf
            line_c = QColor(255, 255, 255, 16)
            p.setPen(QPen(line_c, 1))
            sx, sy = r.left(), y0 + (y0 - vy) * 0.9
            p.drawLine(QPointF(sx, sy), QPointF(vx, vy))
            prog = ((self.t * speed * 0.6) + off) % 1.0              # a light pulse along the line
            px = sx + (vx - sx) * prog
            py = sy + (vy - sy) * prog
            length = 70 * (1 - prog * 0.6)
            dx, dy = (vx - sx), (vy - sy)
            d = math.hypot(dx, dy) or 1
            ex, ey = px - dx / d * length, py - dy / d * length
            lg = QLinearGradient(QPointF(ex, ey), QPointF(px, py))
            a = QColor(g)
            a.setAlpha(0)
            b = QColor(g)
            b.setAlpha(int(220 * (1 - prog * 0.7)))
            lg.setColorAt(0, a)
            lg.setColorAt(1, b)
            p.setPen(QPen(lg, 2.2, Qt.SolidLine, Qt.RoundCap))
            p.drawLine(QPointF(ex, ey), QPointF(px, py))
        # dust
        p.setPen(Qt.NoPen)
        for x, y, ph, sz in self.dust:
            yy = (y - self.t * 0.012 * sz) % 1.0
            alpha = int(70 + 70 * math.sin(self.t * 1.5 + ph))
            c = QColor(g)
            c.setAlpha(max(0, alpha))
            p.setBrush(c)
            p.drawEllipse(QPointF(r.left() + x * r.width(), r.top() + yy * r.height()), sz * 0.7, sz * 0.7)
        p.setClipping(False)
        p.setPen(QPen(QColor(theme.BORDER_HI), 1))
        p.setBrush(Qt.NoBrush)
        p.drawPath(path)
        p.end()


# ---------------------------------------------------------------------------------------------- headline reveal
class RevealTitle(QWidget):
    """A big headline: 'first part' in white + 'second part' in soft grey, revealed word by word (each word slides
    up and sharpens). icon: name of a dotted icon shown after the first part."""
    def __init__(self, first='', second='', size=34, icon=None):
        super().__init__()
        self.first, self.second, self.size, self.icon = first, second, size, icon
        self.progress = 1.0
        self.anim = QVariantAnimation(self, duration=1100, startValue=0.0, endValue=1.0,
                                      easingCurve=QEasingCurve.OutCubic)
        self.anim.valueChanged.connect(self._p)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        self._lines = []

    def _p(self, v):
        self.progress = float(v)
        self.update()

    def set_text(self, first, second='', icon=None, animate=True):
        self.first, self.second = first, second
        if icon is not None:
            self.icon = icon
        self._layout_words()
        if animate and ANIMATE:
            self.anim.stop()
            self.anim.start()
        else:
            self.progress = 1.0
        self.updateGeometry()
        self.update()

    def reveal(self):
        if ANIMATE:
            self.anim.stop()
            self.anim.start()

    def _words(self):
        out = [(w, 0) for w in self.first.split()]
        if self.icon and out:
            out.append(('\0icon', 0))
        out += [(w, 1) for w in self.second.split()]
        return out

    def _layout_words(self):
        f = theme.display_font(self.size)
        fm = QFontMetrics(f)
        space, width = fm.horizontalAdvance(' '), max(200, self.width())
        lines, line, x = [], [], 0
        for word, tone in self._words():
            wd = int(self.size * 1.25) if word == '\0icon' else fm.horizontalAdvance(word)
            if line and x + wd > width:
                lines.append(line)
                line, x = [], 0
            line.append((word, tone, x, wd))
            x += wd + space
        if line:
            lines.append(line)
        self._lines = lines
        self._lh = fm.height() * 1.05
        self.setMinimumHeight(int(self._lh * max(1, len(lines))) + 6)

    def resizeEvent(self, e):
        self._layout_words()
        super().resizeEvent(e)

    def sizeHint(self):
        return QSize(600, int(getattr(self, '_lh', self.size * 1.6) * max(1, len(self._lines))) + 6)

    def paintEvent(self, _):
        if not self._lines:
            self._layout_words()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setRenderHint(QPainter.TextAntialiasing)
        f = theme.display_font(self.size)
        p.setFont(f)
        fm = QFontMetrics(f)
        total = sum(len(l) for l in self._lines) or 1
        i = 0
        for li, line in enumerate(self._lines):
            base = li * self._lh + fm.ascent() + 2
            for word, tone, x, wd in line:
                a = max(0.0, min(1.0, self.progress * (total + 2) - i))       # this word's own progress
                i += 1
                if a <= 0:
                    continue
                dy = (1 - a) * self.size * 0.45
                col = QColor(theme.TEXT if tone == 0 else theme.SOFT)
                if word == '\0icon':
                    pm = theme.dot_pixmap(self.icon, int(self.size * 0.95))
                    p.setOpacity(a)
                    p.drawPixmap(int(x + self.size * 0.12), int(base - fm.ascent() * 0.86 + dy), pm)
                    p.setOpacity(1)
                    continue
                if a < 1:                                          # a soft 'blur' while the word arrives
                    ghost = QColor(col)
                    ghost.setAlphaF(0.18 * a)
                    p.setPen(ghost)
                    for ox in (-2, 2):
                        p.drawText(QPointF(x + ox, base + dy + 1), word)
                col.setAlphaF(a)
                p.setPen(col)
                p.drawText(QPointF(x, base + dy), word)
        p.end()


# ---------------------------------------------------------------------------------------------- small pieces
class DotIcon(Ticker):
    """A dotted pixel icon whose bright dots twinkle."""
    def __init__(self, name, size=26, colour=None):
        super().__init__(fps=12)
        self.name, self.px, self.colour = name, size, colour or theme.ACCENT
        self.setFixedSize(size, size)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        rows = theme.DOTS[self.name]
        n = len(rows)
        cell = self.px / n
        for y, line in enumerate(rows):
            for x, ch in enumerate(line):
                if ch not in '#+':
                    continue
                c = QColor(self.colour)
                if ch == '+':
                    c = QColor(theme.TEXT)
                    c.setAlphaF(0.55 + 0.45 * math.sin(self.t * 4 + x + y))
                p.setPen(Qt.NoPen)
                p.setBrush(c)
                p.drawEllipse(QPointF((x + 0.5) * cell, (y + 0.5) * cell), cell * 0.36, cell * 0.36)
        p.end()


class FloatingTile(Ticker):
    """A glass tile with a word on it that floats up and down a little; lit=True makes it glow green."""
    def __init__(self, title, sub='', lit=False, phase=0.0):
        super().__init__(fps=30)
        self.title, self.sub, self.lit, self.phase = title, sub, lit, phase
        self.setMinimumSize(170, 108)
        self.setToolTip(sub)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        dy = math.sin(self.t * 1.1 + self.phase) * 5
        r = QRectF(8, 10 + dy, self.width() - 16, self.height() - 22)
        if self.lit:
            for i in range(4):
                c = QColor(theme.ACCENT)
                c.setAlpha(26 - i * 5)
                p.setPen(QPen(c, 6 + i * 4))
                p.setBrush(Qt.NoBrush)
                p.drawRoundedRect(r, 16, 16)
            fill = QLinearGradient(r.topLeft(), r.bottomRight())
            fill.setColorAt(0, QColor('#5fd43e'))
            fill.setColorAt(1, QColor('#2f8a1f'))
            p.setPen(QPen(QColor('#9bff7c'), 1))
            p.setBrush(fill)
        else:
            fill = QLinearGradient(r.topLeft(), r.bottomRight())
            fill.setColorAt(0, QColor('#162216'))
            fill.setColorAt(1, QColor('#0a110a'))
            p.setPen(QPen(QColor(theme.BORDER_HI), 1))
            p.setBrush(fill)
        p.drawRoundedRect(r, 16, 16)
        p.setPen(QColor('#061005' if self.lit else theme.TEXT))
        p.setFont(theme.display_font(15, QFont.DemiBold if self.lit else QFont.Normal))
        p.drawText(r.adjusted(10, 0, -10, -16 if self.sub else 0), Qt.AlignCenter, self.title)
        if self.sub:
            p.setFont(theme.body_font(8.5))
            p.setPen(QColor('#0d2a08' if self.lit else theme.MUTED))
            p.drawText(r.adjusted(10, 30, -10, 0), Qt.AlignCenter, self.sub)
        p.end()


def count_up(label, value, duration=900, suffix=''):
    """Animate a QLabel's number from 0 to value (just sets it when animations are off)."""
    try:
        target = int(value)
    except (TypeError, ValueError):
        label.setText(str(value))
        return
    if not ANIMATE or target == 0:
        label.setText(f'{target}{suffix}')
        return
    anim = QVariantAnimation(label, duration=duration, startValue=0, endValue=target,
                             easingCurve=QEasingCurve.OutCubic)
    anim.valueChanged.connect(lambda v: label.setText(f'{int(v)}{suffix}'))
    anim.start(QVariantAnimation.DeleteWhenStopped)


def fade_in(widget, distance=22, duration=420):
    """A page arriving: fades in and slides up a little. The effect is removed afterwards (tables stay fast)."""
    if not ANIMATE or widget is None:
        return
    eff = QGraphicsOpacityEffect(widget)
    eff.setOpacity(0.0)
    widget.setGraphicsEffect(eff)
    a = QPropertyAnimation(eff, b'opacity', widget)
    a.setDuration(duration)
    a.setStartValue(0.0)
    a.setEndValue(1.0)
    a.setEasingCurve(QEasingCurve.OutCubic)
    end = widget.pos()
    m = QPropertyAnimation(widget, b'pos', widget)
    m.setDuration(duration)
    m.setStartValue(end + QPointF(0, distance).toPoint())
    m.setEndValue(end)
    m.setEasingCurve(QEasingCurve.OutCubic)
    a.finished.connect(lambda: widget.setGraphicsEffect(None))
    a.start(QPropertyAnimation.DeleteWhenStopped)
    m.start(QPropertyAnimation.DeleteWhenStopped)


def glass_line():
    """A thin divider line."""
    f = QFrame()
    f.setFixedHeight(1)
    f.setStyleSheet(f'background: {theme.BORDER_HI}; border: none;')
    return f