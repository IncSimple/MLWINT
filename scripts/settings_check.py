"""GUI step G4 check: the Settings tab, without clicking (built off-screen). Save as MLWINT/scripts/settings_check.py
Run from the MLWINT folder:
    experiments/ember2024/.venv/Scripts/python.exe scripts/settings_check.py
Uses a TEMPORARY settings file and a TEMPORARY keys file: your real config/ files are not read or changed, and no
key test goes to the internet (the services are replaced by a stand-in). Checks:
  1 settings file: defaults when missing, memory days kept within 1-365, unknown entries ignored
  2 keys: saved, shown masked, a too-short key refused, an empty box keeps the saved key, Remove clears them
  3 Test keys reports what each service answered (stand-in services)
  4 memory days: saved and used straight away
  5 models folder: a folder without models is refused; a valid one is used; 'Use default' goes back
  6 scan choices kept between sessions, Reset brings back the defaults, switching 'keep' off forgets them
  7 changing keys / models makes the next scan reload its tools
  8 health check lists every part
  9 the command line uses the settings too (memory days)
Writes reports/gui/settings-check-g4.json.
"""
import json, os, sys, tempfile
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402
import src.app_settings as app_settings  # noqa: E402
import src.detection.phase3_reputation as rep  # noqa: E402
from src.detection import scan_memory  # noqa: E402
from src.gui.app import MainWindow  # noqa: E402
from src.gui.settings_tab import SettingsTab  # noqa: E402

MESSAGES = []
QMessageBox.information = lambda *a, **k: MESSAGES.append(('info', a[2] if len(a) > 2 else ''))
QMessageBox.warning = lambda *a, **k: MESSAGES.append(('warning', a[2] if len(a) > 2 else ''))
QMessageBox.question = lambda *a, **k: QMessageBox.Yes                  # 'Yes' to every question


def main():
    app = QApplication.instance() or QApplication(sys.argv[:1])
    checks = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        sp, kp = tmp / 'settings.json', tmp / 'keys.json'

        # 1 settings file
        d = app_settings.load_settings(sp)
        sp.write_text(json.dumps(dict(memory_days=999, unknown='x', models_dir='')), encoding='utf-8')
        d2 = app_settings.load_settings(sp)
        checks.append(('1 settings: defaults, limits, unknown entries ignored', d == dict(app_settings.DEFAULTS)
                       and d2['memory_days'] == 365 and 'unknown' not in d2, f'999 days -> {d2["memory_days"]}'))
        sp.unlink()

        # 2 keys
        t = SettingsTab(settings_path=sp, keys_path=kp)
        mb, vt = 'mb' + 'k' * 46, 'vt' + 'q' * 62
        t.key_edit['malwarebazaar'].setText('short')
        n = len(MESSAGES)
        t.save_keys()
        refused = not kp.exists() and len(MESSAGES) > n
        t.key_edit['malwarebazaar'].setText(mb)
        t.save_keys()
        t.key_edit['virustotal'].setText(vt)
        t.save_keys()                                              # the MalwareBazaar box is empty now: kept
        saved = json.loads(kp.read_text(encoding='utf-8'))
        shown = t.key_state['malwarebazaar'].text()
        ok = (refused and saved == dict(malwarebazaar=mb, virustotal=vt) and shown == 'set (mbkk...kk)'
              and not t.key_edit['virustotal'].text() and mb not in shown)
        t.remove_keys()
        cleared = json.loads(kp.read_text(encoding='utf-8')) == {}
        checks.append(('2 keys saved, masked, short key refused, removed', ok and cleared,
                       f'shown as "{shown}", removed: {cleared}'))

        # 3 test keys with stand-in services
        class FakeRep:
            def __init__(self, keys):
                self.keys = keys

            def lookup(self, sha):
                return dict(malwarebazaar=dict(status='found', family='EICAR'), virustotal=dict(status='error',
                                                                                             reason='HTTP 401'))
        real_rep, real_keys = rep.Reputation, rep.load_keys
        rep.Reputation, rep.load_keys = FakeRep, lambda: dict(malwarebazaar='x', virustotal='y')
        n = len(MESSAGES)
        try:
            t.test_keys()
        finally:
            rep.Reputation, rep.load_keys = real_rep, real_keys
        msg = MESSAGES[-1][1] if len(MESSAGES) > n else ''
        checks.append(('3 Test keys reports each service', 'malwarebazaar: works' in msg
                       and 'virustotal: problem - HTTP 401' in msg and 'EICAR' in msg, msg.split('\n')[0]))

        # 4 memory days
        old_days = scan_memory.MAX_AGE_DAYS
        t.days.setValue(90)
        checks.append(('4 memory days saved and used', app_settings.load_settings(sp)['memory_days'] == 90
                       and scan_memory.MAX_AGE_DAYS == 90, '90 days'))
        scan_memory.MAX_AGE_DAYS = old_days

        # 5 models folder
        empty = tmp / 'empty'
        empty.mkdir()
        good = tmp / 'models'
        for part in ('phase1', 'phase2'):
            (good / part).mkdir(parents=True)
            (good / part / 'manifest.json').write_text('{}', encoding='utf-8')
        t.set_models(str(empty))
        refused = app_settings.load_settings(sp)['models_dir'] == ''
        t.set_models(str(good))
        used = app_settings.load_settings(sp)['models_dir'] == str(good) and t.models_state.text() == 'OK'
        t.set_models('')
        back = app_settings.load_settings(sp)['models_dir'] == '' and t.models_state.text() == 'default models'
        checks.append(('5 models folder checked before use', refused and used and back,
                       f'empty refused {refused}, valid used {used}, default {back}'))

        # 6 scan choices kept between sessions
        w = MainWindow(settings_path=sp)
        w.add_paths([str(tmp)])
        w.scope_pc.setChecked(True)
        w.include_windows.setChecked(True)
        w.large.setChecked(True)
        w.deep_all.setChecked(True)
        w.types.set_types({'win32', 'win64', 'dotnet'})
        w.keep_scan_options()
        w.close()
        w2 = MainWindow(settings_path=sp)
        o = w2.scan_options()
        kept = (o['scope'] == 'pc' and o['include_windows'] and o['large'] and o['deep_all']
                and o['types'] == ['dotnet', 'win32', 'win64'] and o['paths'] == [str(tmp)]
                and w2.combos['evidence'].currentText() == 'all' and not w2.fresh.isChecked())
        w2.on_settings_changed('reset-options')
        o2 = w2.scan_options()
        reset = (o2['scope'] == 'files' and not o2['large'] and not o2['deep_all'] and o2['paths'] == []
                 and app_settings.load_settings(sp)['scan_options'] == {})
        w2.settings_tab.remember.setChecked(False)
        w2.large.setChecked(True)
        w2.keep_scan_options()
        w2.close()
        w3 = MainWindow(settings_path=sp)
        off = not w3.large.isChecked() and app_settings.load_settings(sp)['remember_options'] is False
        checks.append(('6 scan choices kept, Reset, keep switched off', kept and reset and off,
                       f'kept {kept}, reset {reset}, off {off}'))

        # 7 keys / models change -> tools reloaded
        w3.tools_cache.update(key=('x', 'off'), tools={})
        w3.on_settings_changed('keys')
        k1 = not w3.tools_cache
        w3.tools_cache.update(key=('x', 'off'), tools={})
        w3.on_settings_changed('models')
        checks.append(('7 new keys / models: next scan reloads tools', k1 and not w3.tools_cache,
                       w3.status.text()))

        # 8 health
        rows = w3.settings_tab.run_health()
        names = [r[0] for r in rows]
        checks.append(('8 health check lists every part', len(rows) == 8 and rows[0][1] and 'Speakeasy' in ' '.join(names),
                       '; '.join(f'{n}: {"OK" if ok else "MISSING"}' for n, ok, _ in rows)))
        tabs = [w3.tabs.tabText(i) for i in range(w3.tabs.count())]
        w3.close()

        # 9 command line uses the settings
        import mlwint_analyse as cli
        real_file = app_settings.SETTINGS_FILE
        app_settings.SETTINGS_FILE = sp
        sp.write_text(json.dumps(dict(memory_days=12)), encoding='utf-8')
        try:
            cli.load_tools(say=lambda s: None, memory=False)
            used = scan_memory.MAX_AGE_DAYS == 12
        finally:
            app_settings.SETTINGS_FILE = real_file
            scan_memory.MAX_AGE_DAYS = old_days
        checks.append(('9 command line uses the settings (memory days)', used and 'Settings' in tabs,
                       f'MAX_AGE_DAYS was 12: {used}; tabs {tabs}'))

    ok = True
    for name, passed, detail in checks:
        ok &= bool(passed)
        print(f'{"PASS" if passed else "FAIL"}  {name:<52} {str(detail)[:110]}')
    status = 'GUI_G4_CHECKED' if ok else 'GUI_G4_FAILED'
    out = ROOT / 'reports/gui/settings-check-g4.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(status=status, checks=[dict(name=n, passed=bool(p), detail=str(d))
                                                          for n, p, d in checks]), indent=1), encoding='utf-8')
    print(f'\n{status}: {out}')


if __name__ == '__main__':
    main()