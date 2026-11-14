"""MLWINT GUI step G4: Settings tab. Save as MLWINT/src/gui/settings_tab.py
  1 Hash lookup keys   - you type your own MalwareBazaar / VirusTotal keys; shown masked; saved only on this PC in
                         config/intel_keys.json; Test sends ONE harmless public hash (the EICAR test file)
  2 Scan options       - keep my scan choices and folder list between sessions; reset them; control animations
  3 Memory             - after how many days a remembered file is checked again; forget everything
  4 Models             - a different models folder (checked before it is used)
  5 Health check       - is every part of MLWINT in place (detectors, capa, Speakeasy, ATT&CK data, Defender, PDF)
  6 Privacy            - what MLWINT does and never does
Settings are saved in config/mlwint_settings.json (src/app_settings.py); the command line uses them too.
"""
import json, os
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (QCheckBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMessageBox, QScrollArea, QSpinBox, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from src.app_settings import MEMORY_DAYS_RANGE, load_settings, models_problem, save_settings
from .theme import PillButton
from .worker import ROOT, cli

EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
SERVICES = (('malwarebazaar', 'MalwareBazaar key', 'MLWINT_MALWAREBAZAAR_KEY',
             'Free: sign in at auth.abuse.ch and copy your Auth-Key'),
            ('virustotal', 'VirusTotal key (optional)', 'MLWINT_VIRUSTOTAL_KEY',
             'Free account at virustotal.com > your profile > API key (personal use; 4 lookups a minute)'))
PRIVACY = ('<b>What MLWINT does:</b> it reads files to check them and writes its own reports, memory and settings '
           'in the MLWINT folder.<br><b>What it never does:</b> delete, move, quarantine, run or upload your files. '
           'Every step in a report is for you to do.<br><b>What leaves this PC:</b> nothing - unless you switch '
           'Hash lookup on; then only SHA-256 fingerprints are sent to the services whose keys you entered. Never '
           'the file, its name or its folder.<br><b>Large-file check:</b> Microsoft Defender is asked to scan in '
           'report-only mode: it changes nothing.')


def mask(key):
    return f'set ({key[:4]}...{key[-2:]})' if key and len(key) > 8 else ('set' if key else 'not set')


def health():
    """(part, ok, detail) for everything MLWINT needs. Only checks that files are there - nothing is run."""
    from src.detection import phase2_deepcheck, phase2_evidence, phase3_attack, large_files
    from src.app_settings import models_dir
    models = models_dir() or ROOT / 'models'
    out = []
    for part, name in (('phase1', 'Detectors (Phase 1)'), ('phase2', 'Family / behaviour models (Phase 2)')):
        m = models / part / 'manifest.json'
        out.append((name, m.is_file(), str(m.parent) if m.is_file() else f'missing: {m}'))
    out.append(('capa (code check)', phase2_evidence.CAPA_PYTHON.is_file() and phase2_evidence.CAPA_SOURCE.is_dir(),
                str(phase2_evidence.CAPA_SOURCE)))
    out.append(('Speakeasy (safe simulation)', phase2_deepcheck.SPEAKEASY.is_file(), str(phase2_deepcheck.SPEAKEASY)))
    out.append(('MITRE ATT&CK data', phase3_attack.DATA.is_file(), str(phase3_attack.DATA)))
    exe = large_files.mpcmdrun()
    out.append(('Microsoft Defender scanner (large files)', exe is not None, str(exe) if exe else 'not found'))
    try:
        from src.report import plain_report  # noqa: F401
        out.append(('Easy-to-read PDF reports', True, 'Qt PDF writer'))
    except Exception as e:                                         # pragma: no cover - shown to the user
        out.append(('Easy-to-read PDF reports', False, str(e)))
    from src.detection.phase3_reputation import load_keys
    keys = load_keys()
    out.append(('Hash lookup keys', True, ', '.join(keys) + ' set' if keys else 'none set (hash lookup stays off)'))
    return out


class SettingsTab(QWidget):
    changed = Signal(str)               # 'keys', 'models', 'memory', 'options', 'appearance'

    def __init__(self, memory_getter=None, settings_path=None, keys_path=None):
        super().__init__()
        from src.detection import phase3_reputation
        self.settings_path = settings_path
        self.keys_path = Path(keys_path) if keys_path else phase3_reputation.KEYS_FILE
        self.memory_getter = memory_getter
        self.settings = load_settings(settings_path)

        # ---- 1 keys
        keys_box = QGroupBox('Hash lookup keys (optional)')
        kf = QFormLayout(keys_box)
        self.key_edit, self.key_state = {}, {}
        for name, label, env, how in SERVICES:
            e = QLineEdit()
            e.setEchoMode(QLineEdit.Password)
            e.setPlaceholderText('paste your key here (leave empty to keep the saved one)')
            e.setToolTip(how)
            state = QLabel()
            row = QHBoxLayout()
            row.addWidget(e, 1)
            row.addWidget(state)
            kf.addRow(label + ':', row)
            self.key_edit[name], self.key_state[name] = e, state
        self.show_keys = QCheckBox('show what I type')
        self.show_keys.toggled.connect(lambda on: [e.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)
                                                   for e in self.key_edit.values()])
        self.save_keys_btn, self.remove_keys_btn = PillButton('Save keys', 'ghost'), PillButton('Remove saved keys', 'ghost')
        self.test_keys_btn = PillButton('Test keys', 'ghost', 'shield')
        self.test_keys_btn.setToolTip('Looks up ONE harmless public fingerprint (the EICAR anti-virus test file) with '
                                      'your keys. Nothing about your PC is sent.')
        self.save_keys_btn.clicked.connect(self.save_keys)
        self.remove_keys_btn.clicked.connect(self.remove_keys)
        self.test_keys_btn.clicked.connect(self.test_keys)
        kb = QHBoxLayout()
        for w in (self.show_keys, self.save_keys_btn, self.remove_keys_btn, self.test_keys_btn):
            kb.addWidget(w)
        kb.addStretch()
        kf.addRow(kb)
        self.keys_note = QLabel()
        self.keys_note.setWordWrap(True)
        kf.addRow(self.keys_note)

        # ---- 2 scan options (+ appearance)
        opt_box = QGroupBox('Scan options and appearance')
        ol = QVBoxLayout(opt_box)
        self.animations = QCheckBox('Animations (the moving orb, light streaks and page slides; switch off on '
                                    'slow PCs)')
        self.animations.setChecked(bool(self.settings.get('animations', True)))
        self.animations.toggled.connect(self.save_animations)
        ol.addWidget(self.animations)
        self.remember = QCheckBox('Keep my scan choices and folder list between sessions')
        self.remember.setChecked(bool(self.settings['remember_options']))
        self.remember.toggled.connect(self.save_remember)
        self.reset_btn = PillButton('Reset scan options to the defaults', 'ghost')
        self.reset_btn.clicked.connect(lambda: self.changed.emit('reset-options'))
        row = QHBoxLayout()
        row.addWidget(self.remember)
        row.addWidget(self.reset_btn)
        row.addStretch()
        ol.addLayout(row)

        # ---- 3 memory
        mem_box = QGroupBox('Memory (remembered results)')
        ml = QHBoxLayout(mem_box)
        self.days = QSpinBox()
        self.days.setRange(*MEMORY_DAYS_RANGE)
        self.days.setValue(self.settings['memory_days'])
        self.days.setSuffix(' days')
        self.days.valueChanged.connect(self.save_days)
        self.memory_label = QLabel()
        self.forget_btn = PillButton('Forget remembered results', 'ghost')
        self.forget_btn.clicked.connect(self.forget)
        ml.addWidget(QLabel('Check a remembered file again after'))
        ml.addWidget(self.days)
        ml.addWidget(self.memory_label)
        ml.addStretch()
        ml.addWidget(self.forget_btn)

        # ---- 4 models
        mod_box = QGroupBox('Models folder')
        mdl = QHBoxLayout(mod_box)
        self.models_edit = QLineEdit(self.settings['models_dir'])
        self.models_edit.setPlaceholderText(f'default: {ROOT / "models"}')
        self.models_edit.setReadOnly(True)
        self.models_state = QLabel()
        browse, default = PillButton('Choose folder...', 'ghost', 'scan'), PillButton('Use default', 'ghost')
        browse.clicked.connect(self.pick_models)
        default.clicked.connect(lambda: self.set_models(''))
        for w in (self.models_edit, browse, default, self.models_state):
            mdl.addWidget(w, 1 if w is self.models_edit else 0)

        # ---- 5 health
        health_box = QGroupBox('Health check')
        hl = QVBoxLayout(health_box)
        self.health_table = QTableWidget(0, 3)
        self.health_table.setHorizontalHeaderLabels(['Part', 'Status', 'Where'])
        self.health_table.verticalHeader().setVisible(False)
        self.health_table.verticalHeader().setDefaultSectionSize(26)
        self.health_table.setWordWrap(False)
        self.health_table.setEditTriggers(QTableWidget.NoEditTriggers)
        hh = self.health_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        self.health_btn = PillButton('Check again', 'ghost', 'pulse')
        self.health_btn.clicked.connect(self.run_health)
        hl.addWidget(self.health_table)
        hl.addWidget(self.health_btn, 0, Qt.AlignLeft)

        # ---- 6 privacy
        priv_box = QGroupBox('Privacy and safety')
        pl = QVBoxLayout(priv_box)
        priv = QLabel(PRIVACY)
        priv.setWordWrap(True)
        pl.addWidget(priv)
        folder = PillButton('Open the MLWINT settings folder', 'ghost')
        folder.clicked.connect(lambda: os.startfile(self.keys_path.parent) if self.keys_path.parent.is_dir() else None)
        pl.addWidget(folder, 0, Qt.AlignLeft)

        inner = QWidget()
        lay = QVBoxLayout(inner)
        for box in (keys_box, opt_box, mem_box, mod_box, health_box, priv_box):
            lay.addWidget(box)
        lay.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        self.refresh()

    # ------------------------------------------------------------------ helpers
    def refresh(self):
        self.update_keys_state()
        self.update_memory()
        self.update_models_state()
        self.run_health()

    def _save(self):
        save_settings(self.settings, self.settings_path)

    # ------------------------------------------------------------------ keys
    def saved_keys(self):
        try:
            return {k: v for k, v in json.loads(self.keys_path.read_text(encoding='utf-8')).items() if v}
        except (OSError, ValueError):
            return {}

    def update_keys_state(self):
        saved = self.saved_keys()
        notes = []
        for name, _, env, _ in SERVICES:
            self.key_state[name].setText(mask(saved.get(name, '')))
            if os.environ.get(env):
                notes.append(f'{env} is set in your environment and is used instead of the saved key.')
        notes.append(f'Saved only on this PC in {self.keys_path}. Never share, upload or commit that file.')
        self.keys_note.setText(' '.join(notes))
        self.remove_keys_btn.setEnabled(bool(saved))

    def save_keys(self):
        saved = self.saved_keys()
        typed = {name: self.key_edit[name].text().strip() for name, *_ in SERVICES}
        if not any(typed.values()):
            QMessageBox.information(self, 'MLWINT', 'Type or paste a key first.')
            return
        bad = [n for n, v in typed.items() if v and (len(v) < 16 or any(c.isspace() for c in v))]
        if bad:
            QMessageBox.warning(self, 'MLWINT', 'That does not look like a whole key (too short or contains spaces): '
                                + ', '.join(bad))
            return
        saved.update({k: v for k, v in typed.items() if v})
        self.keys_path.parent.mkdir(parents=True, exist_ok=True)
        self.keys_path.write_text(json.dumps(saved, indent=1), encoding='utf-8')
        for e in self.key_edit.values():
            e.clear()
        self.update_keys_state()
        self.run_health()
        self.changed.emit('keys')

    def remove_keys(self):
        if QMessageBox.question(self, 'MLWINT', 'Remove the saved hash lookup keys from this PC? Hash lookup will '
                                                'stay off until you add a key again.') != QMessageBox.Yes:
            return
        try:
            self.keys_path.write_text('{}', encoding='utf-8')
        except OSError as e:
            QMessageBox.warning(self, 'MLWINT', str(e))
        self.update_keys_state()
        self.run_health()
        self.changed.emit('keys')

    def test_keys(self):
        from src.detection.phase3_reputation import Reputation, load_keys, opinion
        keys = load_keys()
        if not keys:
            QMessageBox.information(self, 'MLWINT', 'No key saved yet.')
            return
        QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            res = Reputation(keys=keys).lookup(EICAR_SHA256)
        finally:
            QGuiApplication.restoreOverrideCursor()
        lines = []
        for service, r in res.items():
            if r['status'] == 'found':
                lines.append(f'{service}: works (knows the EICAR test file)')
            elif r['status'] == 'not_found':
                lines.append(f'{service}: works (answered: not known)')
            else:
                lines.append(f'{service}: problem - {r.get("reason")}')
        QMessageBox.information(self, 'MLWINT - key test', '\n'.join(lines) + '\n\nOnly the EICAR test fingerprint '
                                'was sent.\nIn the meter this would read: ' + opinion(res)[2])

    # ------------------------------------------------------------------ options / memory / models
    def save_remember(self, on):
        self.settings['remember_options'] = bool(on)
        if not on:
            self.settings['scan_options'] = {}
        self._save()
        self.changed.emit('options')

    def save_animations(self, on):
        self.settings['animations'] = bool(on)
        self._save()
        self.changed.emit('appearance')

    def save_days(self, days):
        self.settings['memory_days'] = int(days)
        self._save()
        from src.detection import scan_memory
        scan_memory.MAX_AGE_DAYS = int(days)
        self.changed.emit('memory')

    def update_memory(self):
        mem = self.memory_getter() if self.memory_getter else None
        if mem is None:
            from src.detection.scan_memory import MEMORY_FILE
            try:
                n = len(json.loads(MEMORY_FILE.read_text(encoding='utf-8')).get('files', {}))
            except (OSError, ValueError):
                n = 0
        else:
            n = len(mem)
        self.memory_label.setText(f'({n:,} files remembered now)')

    def forget(self):
        if QMessageBox.question(self, 'MLWINT', 'Forget all remembered results? The next scan will analyse every '
                                                'file again. (Only MLWINT\'s own memory file is cleared.)') \
                != QMessageBox.Yes:
            return
        mem = self.memory_getter() if self.memory_getter else None
        if mem is None:
            from src.detection.scan_memory import ScanMemory
            mem = ScanMemory()
        mem.forget()
        self.update_memory()
        self.changed.emit('memory')

    def pick_models(self):
        d = QFileDialog.getExistingDirectory(self, 'Folder holding phase1 and phase2')
        if d:
            self.set_models(d)

    def set_models(self, folder):
        problem = models_problem(folder)
        if problem:
            QMessageBox.warning(self, 'MLWINT', f'This folder cannot be used: {problem}.')
            return
        self.settings['models_dir'] = str(folder)
        self._save()
        self.models_edit.setText(str(folder))
        self.update_models_state()
        self.run_health()
        self.changed.emit('models')

    def update_models_state(self):
        folder = self.settings.get('models_dir') or ''
        problem = models_problem(folder)
        self.models_state.setText('default models' if not folder else (f'problem: {problem}' if problem else 'OK'))

    # ------------------------------------------------------------------ health
    def run_health(self):
        rows = health()
        self.health_table.setRowCount(0)
        for name, ok, where in rows:
            r = self.health_table.rowCount()
            self.health_table.insertRow(r)
            status = QTableWidgetItem('OK' if ok else 'MISSING')
            status.setForeground(QColor('#2fa35a' if ok else '#e04848'))
            for c, item in enumerate((QTableWidgetItem(name), status, QTableWidgetItem(where))):
                if c == 2:
                    item.setToolTip(where)
                self.health_table.setItem(r, c, item)
        self.health_table.setMinimumHeight(36 + 26 * len(rows))      # every part visible without scrolling
        return rows