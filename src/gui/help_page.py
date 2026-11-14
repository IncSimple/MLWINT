"""MLWINT Help & About page. Save as MLWINT/src/gui/help_page.py
How a file is checked (five [ 01 ]..[ 05 ] columns), what the levels mean, privacy, and the tools MLWINT is built
on as floating glass tiles, with their licences.
"""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget

from . import fx, theme

VERSION = 'MLWINT 1.0'
STEPS = (
    ('Detector', 'A model trained on hundreds of thousands of known safe and harmful Windows programs and PDFs '
                 'says how similar the file is to known malware.'),
    ('Code check', 'For flagged and risky files, capa reads the program\'s code and lists what it can do, mapped to '
                   'MITRE ATT&CK. PDFs are checked for JavaScript, launch actions and hidden files.'),
    ('Safe simulation', 'Speakeasy imitates Windows and watches what a program would try to do - without ever '
                        'really running it.'),
    ('Your PC', 'Where the file came from, whether it was ever run, whether it is running or starts '
                'automatically, and what Microsoft Defender already knows.'),
    ('Outside opinion', 'Optional and off by default: only the file\'s SHA-256 fingerprint is looked up at '
                        'MalwareBazaar / VirusTotal with your own key.'),
)
LEVELS = (('LOW', 'below 20', 'No meaningful sign of malware.'),
          ('GUARDED', '20 - 39', 'Weak warning signs. Fine if you expected the file.'),
          ('ELEVATED', '40 - 59', 'Clear warning signs. Do not open it until you know where it came from.'),
          ('HIGH', '60 - 79', 'Very likely malware. Follow the steps in the report.'),
          ('SEVERE', '80 - 100', 'Malware with harmful behaviour. Follow the steps in the report now.'))
CREDITS = (('capa', 'Mandiant FLARE', 'reads what a program can do', 'Apache License 2.0'),
           ('Speakeasy', 'Mandiant', 'safe simulation of Windows programs', 'MIT License'),
           ('MITRE ATT&CK', 'The MITRE Corporation', 'names and explains attacker techniques',
            '© The MITRE Corporation, used under its terms of use'),
           ('EMBER2024', 'features', 'the file features the detectors read', 'see the EMBER2024 project licence'),
           ('XGBoost · LightGBM', 'models', 'the machine-learning models', 'Apache License 2.0 / MIT License'),
           ('Qt for Python', 'PySide6', 'this window and the PDF reports', 'LGPL v3'))


def _label(text, name=None, wrap=True, align=None):
    lbl = QLabel(text)
    lbl.setWordWrap(wrap)
    if name:
        lbl.setObjectName(name)
    if align is not None:
        lbl.setAlignment(align)
    return lbl


class HelpPage(QWidget):
    def __init__(self):
        super().__init__()
        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(40, 6, 40, 110)
        lay.setSpacing(22)
        lay.addWidget(_label('[ GUIDE ]', 'tag'))
        lay.addWidget(fx.RevealTitle('How MLWINT', 'keeps an eye on your files', 34, 'help'))

        # how a file is checked: five centred columns
        steps = QHBoxLayout()
        steps.setSpacing(18)
        for i, (title, text) in enumerate(STEPS):
            col = QVBoxLayout()
            col.setSpacing(8)
            col.addWidget(_label(f'[ 0{i + 1} ]', 'num', align=Qt.AlignCenter))
            col.addWidget(_label(title, 'cardTitle', align=Qt.AlignCenter))
            col.addWidget(_label(text, 'muted', align=Qt.AlignHCenter | Qt.AlignTop))
            col.addStretch()
            steps.addLayout(col, 1)
        lay.addLayout(steps)
        lay.addWidget(_label('Every step adds points with a written reason; together they make the 0 - 100 threat '
                             'score. A score is a warning based on what MLWINT can see, not proof.', 'soft',
                             align=Qt.AlignCenter))
        lay.addWidget(fx.glass_line())

        # levels
        lv, ll = theme.card('What the levels mean', '[ LEVELS ]')
        grid = QGridLayout()
        grid.setVerticalSpacing(10)
        for i, (level, rng, text) in enumerate(LEVELS):
            grid.addWidget(theme.chip(theme.LEVEL_WORDS[level], theme.LEVEL[level]), i, 0)
            grid.addWidget(_label(f'{level.title()}  ({rng})', wrap=False), i, 1)
            grid.addWidget(_label(text, 'muted'), i, 2)
        grid.setColumnStretch(2, 1)
        ll.addLayout(grid)

        from .settings_tab import PRIVACY
        pv, pl = theme.card('Privacy and safety', '[ PROMISE ]')
        pl.addWidget(_label(PRIVACY, 'soft'))
        pl.addStretch()
        two = QHBoxLayout()
        two.setSpacing(18)
        two.addWidget(lv, 1)
        two.addWidget(pv, 1)
        lay.addLayout(two)

        # built with: floating tiles, like certificates
        built = QHBoxLayout()
        left = QVBoxLayout()
        left.addWidget(_label('[ BUILT WITH ]', 'tag'))
        left.addWidget(fx.RevealTitle('Trusted', 'open tools', 34, 'shield'))
        left.addWidget(_label('MLWINT stands on well-known, open security tools and data. Hover a tile for '
                              'its licence.', 'muted'))
        left.addStretch()
        tiles = QGridLayout()
        tiles.setSpacing(6)
        for i, (name, by, what, licence) in enumerate(CREDITS):
            t = fx.FloatingTile(name, by, lit=(name == 'MITRE ATT&CK'), phase=i * 0.8)
            t.setToolTip(f'{name} ({by}): {what}.\nLicence: {licence}')
            tiles.addWidget(t, i // 3, i % 3)
        built.addLayout(left, 2)
        built.addLayout(tiles, 3)
        lay.addLayout(built)

        credits = QGridLayout()
        credits.setVerticalSpacing(4)
        for i, (name, by, what, licence) in enumerate(CREDITS):
            credits.addWidget(_label(f'{name}', wrap=False), i, 0)
            credits.addWidget(_label(what, 'muted'), i, 1)
            credits.addWidget(_label(licence, 'muted'), i, 2)
        credits.setColumnStretch(1, 1)
        lay.addLayout(credits)

        about = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(theme.logo_pixmap(46))
        about.addWidget(logo)
        about.addWidget(_label(f'<b>{VERSION}</b> - read-only malware check for Windows programs and PDFs.<br>'
                               '<span style="color:#7d8f7d">MLWINT never deletes, moves, quarantines, runs or uploads '
                               'your files.</span>'))
        about.addStretch()
        lay.addLayout(about)
        lay.addStretch()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)