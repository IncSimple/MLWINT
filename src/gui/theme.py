"""MLWINT look: deep green-black, neon-lime light, big light type, glass panels, pill buttons, dotted pixel icons.
Save as MLWINT/src/gui/theme.py
Static pieces only (colours, fonts, the Qt style sheet, logo, dotted icons, pill buttons, cards). Everything that
moves is in fx.py. Inspired by dark cybersecurity designs; the shapes and logo are MLWINT's own.
"""
from PySide6.QtCore import QPointF, QRectF, QSize, Qt, QVariantAnimation, QEasingCurve
from PySide6.QtGui import (QBrush, QColor, QFont, QFontDatabase, QFontMetrics, QIcon, QPainter, QPainterPath,
                           QPalette, QPen, QPixmap, QRadialGradient)
from PySide6.QtWidgets import QApplication, QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

# ---------------------------------------------------------------------------------------------- colours
BG = '#050805'
PANEL = 'rgba(14, 22, 14, 0.82)'      # glass panels
PANEL_SOLID = '#0b120b'
SURFACE = '#0b120b'
SURFACE_2 = '#101a10'
LINE = 'rgba(124, 240, 90, 0.10)'
BORDER = '#172317'
BORDER_HI = '#24382a'
TEXT = '#eef5ee'
SOFT = '#a9b8a9'          # second line of two-tone headlines
MUTED = '#7d8f7d'
ACCENT = '#7cf05a'        # neon lime
ACCENT_DEEP = '#3e9c2a'
ON_ACCENT = '#061005'
WHITE_PILL = '#f1f5f1'
LEVEL = {'LOW': '#6ee07a', 'GUARDED': '#57b8f0', 'ELEVATED': '#f5bd45', 'HIGH': '#ff8d42', 'SEVERE': '#ff4f62'}
LEVEL_WORDS = {'LOW': 'Looks fine', 'GUARDED': 'Worth a look', 'ELEVATED': 'Be careful', 'HIGH': 'Act now',
               'SEVERE': 'Act now'}

DISPLAY = 'Segoe UI'      # set by apply_theme() to the best font this PC has
BODY = 'Segoe UI'


def pick_fonts():
    global DISPLAY, BODY
    fams = set(QFontDatabase.families())
    DISPLAY = next((f for f in ('Segoe UI Variable Display', 'Segoe UI Light', 'Segoe UI') if f in fams), 'Segoe UI')
    BODY = next((f for f in ('Segoe UI Variable Text', 'Segoe UI') if f in fams), 'Segoe UI')


def display_font(pt, weight=QFont.Light):
    f = QFont(DISPLAY)
    f.setPointSizeF(pt)
    f.setWeight(weight)
    return f


def body_font(pt=10.5, weight=QFont.Normal):
    f = QFont(BODY)
    f.setPointSizeF(pt)
    f.setWeight(weight)
    return f


def style_sheet():
    return f"""
* {{ font-family: '{BODY}'; font-size: 10.5pt; color: {TEXT}; }}
QMainWindow, QDialog, QMessageBox {{ background: {BG}; }}
QLabel, QCheckBox, QRadioButton {{ background: transparent; }}
QToolTip {{ background: {SURFACE_2}; color: {TEXT}; border: 1px solid {ACCENT_DEEP}; padding: 6px; border-radius: 6px; }}

QFrame#topbar {{ background: transparent; }}
QLabel#brand {{ font-family: '{DISPLAY}'; font-size: 15pt; font-weight: 600; letter-spacing: 3px; }}
QFrame#statusPill {{ background: rgba(16, 26, 16, 0.9); border: 1px solid {BORDER_HI}; border-radius: 17px; }}
QFrame#statusPill QLabel {{ color: {SOFT}; font-size: 9.5pt; }}
QFrame#floatnav {{ background: rgba(14, 22, 14, 0.96); border: 1px solid {BORDER_HI}; border-radius: 26px; }}
QPushButton#navpill {{ background: transparent; border: none; border-radius: 19px; padding: 9px 18px; color: {SOFT};
                       font-size: 10.5pt; }}
QPushButton#navpill:hover {{ color: {TEXT}; }}
QPushButton#navpill:checked {{ background: #1c2a1c; color: {TEXT}; }}

QFrame#glass, QFrame#card {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 20px; }}
QFrame#statCard {{ background: transparent; border: none; }}
QLabel#tag {{ color: {ACCENT}; font-size: 9pt; letter-spacing: 2px; }}
QLabel#num {{ color: {MUTED}; font-size: 9pt; letter-spacing: 2px; }}
QLabel#cardTitle {{ font-family: '{DISPLAY}'; font-size: 15pt; font-weight: 400; }}
QLabel#muted {{ color: {MUTED}; }}
QLabel#soft {{ color: {SOFT}; }}
QLabel#bigNumber {{ font-family: '{DISPLAY}'; font-size: 34pt; font-weight: 300; }}
QLabel#pageTitle {{ font-family: '{DISPLAY}'; font-size: 30pt; font-weight: 300; }}

QPushButton {{ background: rgba(20, 32, 20, 0.9); color: {TEXT}; border: 1px solid {BORDER_HI}; border-radius: 19px;
               padding: 8px 18px; }}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:pressed {{ background: {BORDER}; }}
QPushButton:disabled {{ color: #4a5a4a; border-color: {BORDER}; }}
QToolButton {{ background: transparent; color: {SOFT}; border: 1px solid {BORDER_HI}; border-radius: 15px;
               padding: 5px 14px; }}
QToolButton:checked, QToolButton:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}

QLineEdit, QComboBox, QSpinBox, QListWidget {{ background: rgba(18, 30, 18, 0.95); color: {TEXT};
               border: 1px solid {BORDER_HI}; border-radius: 12px; padding: 7px 12px;
               selection-background-color: {ACCENT_DEEP}; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {ACCENT}; }}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled, QListWidget:disabled {{ color: #4a5a4a; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{ background: {SURFACE_2}; color: {TEXT}; selection-background-color: {ACCENT_DEEP};
                               border: 1px solid {BORDER_HI}; outline: none; }}
QListWidget::item {{ padding: 4px 2px; }}
QCheckBox, QRadioButton {{ spacing: 9px; }}
QCheckBox::indicator, QRadioButton::indicator {{ width: 17px; height: 17px; border: 1px solid #3a553a;
                                                 background: rgba(18, 30, 18, 0.95); }}
QCheckBox::indicator {{ border-radius: 6px; }}
QRadioButton::indicator {{ border-radius: 9px; }}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {{ background: qradialgradient(cx:0.5, cy:0.5,
        radius:0.6, fx:0.5, fy:0.5, stop:0 {ACCENT}, stop:0.55 {ACCENT}, stop:0.62 #0d1a0d, stop:1 #0d1a0d);
        border-color: {ACCENT}; }}
QCheckBox::indicator:indeterminate {{ background: {ACCENT_DEEP}; border-color: {ACCENT_DEEP}; }}
QCheckBox:disabled, QRadioButton:disabled {{ color: #4a5a4a; }}

QTableWidget {{ background: transparent; color: {TEXT}; border: none; gridline-color: transparent;
                selection-background-color: rgba(124, 240, 90, 0.13); selection-color: {TEXT}; outline: none; }}
QTableWidget::item {{ border-bottom: 1px solid rgba(124, 240, 90, 0.06); padding: 4px 6px; }}
QHeaderView::section {{ background: transparent; color: {MUTED}; border: none;
                        border-bottom: 1px solid {BORDER_HI}; padding: 8px 6px; font-size: 9pt; letter-spacing: 1px; }}
QTableCornerButton::section {{ background: transparent; border: none; }}
QTextBrowser, QPlainTextEdit {{ background: transparent; color: {TEXT}; border: none; }}
QPlainTextEdit#log {{ background: rgba(10, 16, 10, 0.9); border: 1px solid {BORDER}; border-radius: 14px; padding: 8px;
                      color: {MUTED}; font-family: 'Consolas'; font-size: 9pt; }}
QProgressBar {{ background: rgba(124, 240, 90, 0.08); border: none; border-radius: 3px; height: 6px; max-height: 6px;
                color: transparent; }}
QProgressBar::chunk {{ border-radius: 3px; background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                       stop:0 {ACCENT_DEEP}, stop:1 {ACCENT}); }}
QGroupBox {{ border: 1px solid {BORDER}; border-radius: 20px; margin-top: 22px; padding: 18px 16px 14px 16px;
             background: {PANEL}; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 18px; padding: 0 6px; color: {ACCENT}; font-size: 9pt;
                    letter-spacing: 2px; }}
QScrollArea {{ border: none; background: transparent; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QSplitter::handle {{ background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 8px; margin: 4px 2px; }}
QScrollBar::handle:vertical {{ background: #22362a; border-radius: 3px; min-height: 30px; }}
QScrollBar:horizontal {{ background: transparent; height: 8px; margin: 2px 4px; }}
QScrollBar::handle:horizontal {{ background: #22362a; border-radius: 3px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QTabWidget::pane {{ border: none; background: transparent; }}
QMenu {{ background: {SURFACE_2}; color: {TEXT}; border: 1px solid {BORDER_HI}; border-radius: 10px; padding: 6px; }}
QMenu::item {{ padding: 6px 18px; border-radius: 6px; }}
QMenu::item:selected {{ background: rgba(124, 240, 90, 0.16); }}
"""


def apply_theme(app=None):
    """Fusion + dark palette + fonts + style sheet (safe to call more than once)."""
    app = app or QApplication.instance()
    if app is None or app.property('mlwint_theme'):
        return
    pick_fonts()
    app.setStyle('Fusion')
    p = QPalette()
    for role, colour in ((QPalette.Window, BG), (QPalette.WindowText, TEXT), (QPalette.Base, SURFACE_2),
                         (QPalette.AlternateBase, SURFACE), (QPalette.Text, TEXT), (QPalette.Button, SURFACE_2),
                         (QPalette.ButtonText, TEXT), (QPalette.Highlight, ACCENT_DEEP),
                         (QPalette.HighlightedText, '#ffffff'), (QPalette.Link, ACCENT),
                         (QPalette.ToolTipBase, SURFACE_2), (QPalette.ToolTipText, TEXT),
                         (QPalette.PlaceholderText, MUTED)):
        p.setColor(role, QColor(colour))
    app.setPalette(p)
    app.setFont(body_font())
    app.setStyleSheet(style_sheet())
    app.setWindowIcon(app_icon())
    app.setProperty('mlwint_theme', True)


# ---------------------------------------------------------------------------------------------- logo
def logo_pixmap(size=64):
    """MLWINT's mark: a dotted shield with a check (no image files needed)."""
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    s = size / 64.0
    shield = QPainterPath()
    shield.moveTo(32 * s, 5 * s)
    shield.lineTo(55 * s, 14 * s)
    shield.cubicTo(55 * s, 38 * s, 45 * s, 52 * s, 32 * s, 59 * s)
    shield.cubicTo(19 * s, 52 * s, 9 * s, 38 * s, 9 * s, 14 * s)
    shield.closeSubpath()
    glow = QRadialGradient(QPointF(32 * s, 30 * s), 30 * s)
    glow.setColorAt(0, QColor(124, 240, 90, 70))
    glow.setColorAt(1, QColor(124, 240, 90, 0))
    p.fillPath(shield, QBrush(glow))
    pen = QPen(QColor(ACCENT), 3.0 * s, Qt.DotLine if size >= 32 else Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen)
    p.drawPath(shield)
    check = QPainterPath()
    check.moveTo(22 * s, 32 * s)
    check.lineTo(29.5 * s, 39.5 * s)
    check.lineTo(43 * s, 24 * s)
    p.setPen(QPen(QColor(TEXT), 4 * s, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    p.drawPath(check)
    p.end()
    return pm


def app_icon():
    icon = QIcon()
    for s in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(logo_pixmap(s))
    return icon


# ---------------------------------------------------------------------------------------------- dotted pixel icons
DOTS = {   # 9 x 9 pixel art: '#' = dot, '+' = bright dot (twinkles in fx.DotIcon)
    'shield': ['....#....', '..##.##..', '.#.....#.', '.#..+..#.', '.#.+.+.#.', '.#.....#.', '..#...#..',
               '...#.#...', '....#....'],
    'pulse': ['.........', '.........', '....#....', '...#.#...', '#.#...#.#', '.#.....#.', '.....+...',
              '.........', '.........'],
    'scan': ['..###....', '.#...#...', '#..+..#..', '#.+.+.#..', '#..+..#..', '.#...#...', '..###.#..',
             '.......#.', '........#'],
    'clock': ['..#####..', '.#.....#.', '#...+...#', '#...+...#', '#...+++.#', '#.......#', '#.......#',
              '.#.....#.', '..#####..'],
    'gear': ['....#....', '.#.###.#.', '..#...#..', '.#..+..#.', '##.+.+.##', '.#..+..#.', '..#...#..',
             '.#.###.#.', '....#....'],
    'help': ['..#####..', '.#.....#.', '.......#.', '......#..', '....+....', '....#....', '.........',
             '....+....', '.........'],
    'home': ['....#....', '...#.#...', '..#...#..', '.#.....#.', '###...###', '.#..+..#.', '.#.+.+.#.',
             '.#.....#.', '.#######.'],
    'doc': ['.#####...', '.#...##..', '.#....#..', '.#.++.#..', '.#....#..', '.#.++.#..', '.#....#..',
            '.######..', '.........'],
}


def dot_pixmap(name, size=22, colour=ACCENT, bright=TEXT):
    rows = DOTS[name]
    n = len(rows)
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    cell = size / n
    r = cell * 0.36
    for y, line in enumerate(rows):
        for x, ch in enumerate(line):
            if ch in '#+':
                p.setPen(Qt.NoPen)
                p.setBrush(QColor(bright if ch == '+' else colour))
                p.drawEllipse(QPointF((x + 0.5) * cell, (y + 0.5) * cell), r, r)
    p.end()
    return pm


# ---------------------------------------------------------------------------------------------- buttons
class PillButton(QPushButton):
    """'primary': white pill with a green circular arrow (the main action). 'ghost': dark glass pill.
    It is a normal QPushButton (text(), clicked, setEnabled ...) with its own drawing and a soft hover animation."""
    def __init__(self, text, kind='primary', icon=None):
        super().__init__(text)
        self.kind, self.dot = kind, icon
        self._hover = 0.0
        self.anim = QVariantAnimation(self, duration=220, startValue=0.0, endValue=1.0,
                                      easingCurve=QEasingCurve.OutCubic)
        self.anim.valueChanged.connect(self._set_hover)
        self.setCursor(Qt.PointingHandCursor)
        self.setAttribute(Qt.WA_Hover, True)
        self.setMinimumHeight(46 if kind == 'primary' else 40)

    def _set_hover(self, v):
        self._hover = float(v)
        self.update()

    def enterEvent(self, e):
        self.anim.setDirection(QVariantAnimation.Forward)
        self.anim.start()
        super().enterEvent(e)

    def leaveEvent(self, e):
        self.anim.setDirection(QVariantAnimation.Backward)
        self.anim.start()
        super().leaveEvent(e)

    def sizeHint(self):
        fm = QFontMetrics(body_font(10.5, QFont.DemiBold if self.kind == 'primary' else QFont.Normal))
        w = fm.horizontalAdvance(self.text()) + (78 if self.kind == 'primary' else 40 + (26 if self.dot else 0))
        return QSize(w, 46 if self.kind == 'primary' else 40)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        rad = r.height() / 2
        on = self.isEnabled()
        h = self._hover if on else 0.0
        if self.kind == 'primary':
            if h > 0:                                             # soft green glow on hover
                for i in range(3):
                    g = QColor(ACCENT)
                    g.setAlpha(int(28 * h / (i + 1)))
                    p.setPen(QPen(g, 2 + i * 3))
                    p.setBrush(Qt.NoBrush)
                    p.drawRoundedRect(r.adjusted(-i, -i, i, i), rad, rad)
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(WHITE_PILL if on else '#3a463a'))
            p.drawRoundedRect(r, rad, rad)
            d = r.height() - 10
            cx = r.right() - 5 - d / 2 - 0
            circle = QRectF(cx - d / 2, r.top() + 5, d, d)
            p.setBrush(QColor(ACCENT if on else '#56704e'))
            p.drawEllipse(circle)
            c = circle.center()                                   # the arrow turns a little on hover
            off = 2.5 * h
            p.setPen(QPen(QColor(ON_ACCENT), 2.0, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            a, b = QPointF(c.x() - 5 + off, c.y() + 5 - off), QPointF(c.x() + 5 + off, c.y() - 5 - off)
            p.drawLine(a, b)
            p.drawLine(b, QPointF(b.x() - 7, b.y()))
            p.drawLine(b, QPointF(b.x(), b.y() + 7))
            p.setPen(QColor('#0b120b' if on else '#202820'))
            p.setFont(body_font(10.5, QFont.DemiBold))
            p.drawText(QRectF(r.left() + 20, r.top(), r.width() - d - 30, r.height()), Qt.AlignVCenter | Qt.AlignLeft,
                       self.text())
        else:
            border = QColor(ACCENT if h > 0.5 else BORDER_HI)
            p.setPen(QPen(border, 1))
            p.setBrush(QColor(20 + int(8 * h), 32 + int(10 * h), 20 + int(8 * h), 235))
            p.drawRoundedRect(r, rad, rad)
            x = r.left() + 16
            if self.dot:
                p.drawPixmap(int(x), int(r.center().y() - 8), dot_pixmap(self.dot, 16, ACCENT if on else MUTED))
                x += 24
            p.setPen(QColor(TEXT if on else '#4a5a4a'))
            p.setFont(body_font(10.5))
            p.drawText(QRectF(x, r.top(), r.right() - x - 14, r.height()), Qt.AlignVCenter | Qt.AlignLeft,
                       self.text())
        p.end()


# ---------------------------------------------------------------------------------------------- building blocks
def card(title=None, tag=None, name='glass'):
    """A rounded glass card; returns (frame, its vertical layout). tag: the small '[ 01 ]' label above the title."""
    f = QFrame()
    f.setObjectName(name)
    lay = QVBoxLayout(f)
    lay.setContentsMargins(24, 18, 24, 20)
    lay.setSpacing(10)
    if tag:
        t = QLabel(tag)
        t.setObjectName('tag')
        lay.addWidget(t)
    if title:
        h = QLabel(title)
        h.setObjectName('cardTitle')
        lay.addWidget(h)
    return f, lay


def page_title(title, tag, subtitle=''):
    """Big light page title with a small green '[ tag ]' above it (static version; fx.RevealTitle animates)."""
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 8)
    lay.setSpacing(4)
    t = QLabel(f'[ {tag} ]')
    t.setObjectName('tag')
    h = QLabel(title)
    h.setObjectName('pageTitle')
    lay.addWidget(t)
    lay.addWidget(h)
    if subtitle:
        s = QLabel(subtitle)
        s.setObjectName('soft')
        s.setWordWrap(True)
        lay.addWidget(s)
    return w


def stat_card(number, label, colour=TEXT, num_tag=''):
    """A '[ 01 ]' column with a big light number and a label; returns (frame, number label)."""
    f = QFrame()
    f.setObjectName('statCard')
    lay = QVBoxLayout(f)
    lay.setContentsMargins(6, 4, 6, 4)
    lay.setSpacing(2)
    if num_tag:
        t = QLabel(num_tag)
        t.setObjectName('num')
        t.setAlignment(Qt.AlignCenter)
        lay.addWidget(t)
    n = QLabel(str(number))
    n.setObjectName('bigNumber')
    n.setStyleSheet(f'color: {colour};')
    n.setAlignment(Qt.AlignCenter)
    t = QLabel(label)
    t.setObjectName('soft')
    t.setAlignment(Qt.AlignCenter)
    lay.addWidget(n)
    lay.addWidget(t)
    return f, n


def chip(text, colour):
    """A small coloured pill with a dot (used for levels)."""
    c = QColor(colour)
    lbl = QLabel(f'●  {text}')
    lbl.setStyleSheet(f'color: {colour}; background: rgba({c.red()},{c.green()},{c.blue()},26); '
                      f'border: 1px solid rgba({c.red()},{c.green()},{c.blue()},90); border-radius: 11px; '
                      f'padding: 2px 10px; font-size: 9pt;')
    return lbl


def row(*widgets, stretch_last=True):
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    for x in widgets:
        lay.addWidget(x)
    if stretch_last:
        lay.addStretch()
    return w


def bold_font(size=None):
    f = body_font(size or 10.5, QFont.DemiBold)
    return f


GlowPanel = None          # replaced by fx.StreakPanel (kept so old imports fail loudly, not silently)