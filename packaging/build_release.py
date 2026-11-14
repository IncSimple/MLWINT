"""MLWINT release builder (G5). Builds a self-contained copy of MLWINT in dist/MLWINT that runs on any Windows 10/11
x64 PC without Python, Flutter or this project folder, then (optionally) the installer.

Run from the MLWINT folder with the EMBER2024 environment:
    experiments/ember2024/.venv/Scripts/python.exe packaging/build_release.py              (bundle + installer)
    experiments/ember2024/.venv/Scripts/python.exe packaging/build_release.py --no-installer
    experiments/ember2024/.venv/Scripts/python.exe packaging/build_release.py --skip-flutter (reuse the last app build)

To release an update: change version.json ("app" for program changes, "models" for retrained models), run this, and
give people the new MLWINT-Setup-<version>.exe. Installing it over an old version replaces the program and models but
keeps their reports, settings, keys and scan memory (the memory re-checks files by itself when the models change).

What the bundle holds (same layout as this project, so every path in the code stays the same):
    app/                      the Flutter window (MLWINT.exe)
    scripts/ src/             MLWINT's Python code (no caches)
    models/ data/attack/      detectors + classifiers, MITRE ATT&CK data
    tools/capa-source-*/      capa rules and signatures only
    runtime/python/           one Python 3.13 runtime shared by the three environments below
    experiments/{ember2024,capa,speakeasy}/.venv/   each: Scripts/python(w).exe + Lib/site-packages (trimmed)
    version.json
Never copied: config/ (your API keys!), reports/, scan memory, .git, training data, notebooks.
The installer writes each environment's pyvenv.cfg ("home = <install folder>/runtime/python"); this script writes them
for dist/MLWINT itself so the bundle can be tested in place.
"""
import argparse, json, os, re, shutil, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'
OUT = DIST / 'MLWINT'
APP_BUILD = ROOT / 'mlwint_app/build/windows/x64/runner/Release'
ENVS = ('ember2024', 'capa', 'speakeasy')
CAPA_SOURCE = 'tools/capa-source-v9.4.0'

# site-packages never needed at run time (checked by tracing a deep scan of a program, a .NET DLL and a PDF)
SKIP_PACKAGES = {
    'pip', 'matplotlib', 'mpl_toolkits', 'pil', 'pillow', 'fonttools', 'hf_xet', 'pyside6_addons',
    'pyside6_webengine', 'pyside6_pdf', 'pyinstaller', 'pyinstaller_hooks_contrib', '_pyinstaller_hooks_contrib',
    'pytest', '_pytest', 'ipykernel', 'ipython', 'jupyter', 'notebook',
}
# the only Qt parts MLWINT uses (QtCore, QtGui, QtWidgets: PDF reports and the engine's shared helpers)
QT_KEEP_FILES = re.compile(r'^(__init__\.py|_config\.py|_git_pyside_version\.py|py\.typed|qt\.conf|'
                           r'Qt(Core|Gui|Widgets)\.pyd|pyside6\.abi3\.dll|Qt6(Core|Gui|Widgets)\.dll|'
                           r'(msvcp|vcruntime|concrt)[0-9_a-z]*\.dll)$', re.I)
QT_KEEP_DIRS = {'support'}
QT_KEEP_PLUGINS = {'platforms', 'imageformats', 'styles', 'iconengines'}
# parts of the Python runtime nobody needs
SKIP_RUNTIME = {'lib/test', 'lib/idlelib', 'lib/tkinter', 'lib/turtledemo', 'lib/site-packages', 'tcl', 'tools',
                'doc', 'include', 'libs', 'scripts'}


def say(*a):
    print(*a, flush=True)


def size_of(p):
    return sum(f.stat().st_size for f in Path(p).rglob('*') if f.is_file())


def mb(n):
    return f'{n / 1024 ** 2:,.0f} MB'


def ignore_caches(_, names):
    return [n for n in names if n == '__pycache__' or n.endswith(('.pyc', '.pyo'))]


def ignore_libs(folder, names):
    """Inside the Python environments: no caches and no libraries' own test suites (never used at run time; they
    also hold very long file names that can pass Windows' 260-character path limit)."""
    return ignore_caches(folder, names) + [n for n in names if n.lower() in ('tests', 'test')
                                            and (Path(folder) / n).is_dir()]


def copy_tree(src, dst, ignore=ignore_caches):
    shutil.copytree(src, dst, ignore=ignore, dirs_exist_ok=True)


def dist_name(n):
    """'scikit_learn-1.9.1.dist-info' -> 'scikit_learn'"""
    return re.split(r'-\d', n, maxsplit=1)[0].lower().replace('-', '_')


# ---------------------------------------------------------------------------------------------- steps
def versions():
    v = json.loads((ROOT / 'version.json').read_text(encoding='utf-8'))
    if not re.fullmatch(r'\d+\.\d+\.\d+', v['app']):
        raise SystemExit('version.json "app" must look like 1.2.3')
    return v


def flutter_exe():
    found = shutil.which('flutter')
    if found:
        return found
    guess = Path.home() / 'dev/flutter/bin/flutter.bat'
    if guess.is_file():
        return str(guess)
    raise SystemExit('flutter not found: add it to PATH')


def build_flutter(app_version):
    pub = ROOT / 'mlwint_app/pubspec.yaml'
    text = pub.read_text(encoding='utf-8')
    build = int(time.strftime('%y%m%d%H'))           # increases with every build
    new = re.sub(r'^version:.*$', f'version: {app_version}+{build}', text, count=1, flags=re.M)
    if new != text:
        pub.write_text(new, encoding='utf-8')
    say(f'Building the window (Flutter), version {app_version}+{build} ...')
    subprocess.run([flutter_exe(), 'build', 'windows', '--release'], cwd=ROOT / 'mlwint_app', check=True,
                   shell=False)


def base_python():
    cfg = (ROOT / 'experiments/ember2024/.venv/pyvenv.cfg').read_text(encoding='utf-8')
    home = Path(re.search(r'^home\s*=\s*(.+)$', cfg, re.M).group(1).strip())
    if not (home / 'python.exe').is_file():
        raise SystemExit(f'base Python not found at {home}')
    for env in ENVS[1:]:
        other = (ROOT / f'experiments/{env}/.venv/pyvenv.cfg').read_text(encoding='utf-8')
        if str(home).lower() not in other.lower():
            raise SystemExit(f'{env} uses a different base Python: rebuild it from {home}')
    return home


def copy_runtime(home):
    say(f'Copying the Python runtime from {home} ...')
    dst = OUT / 'runtime/python'

    def ignore(folder, names):
        rel = Path(folder).relative_to(home).as_posix().lower()
        out = ignore_caches(folder, names)
        for n in names:
            if (f'{rel}/{n}'.lstrip('./').lower() if rel != '.' else n.lower()) in SKIP_RUNTIME:
                out.append(n)
        return out

    copy_tree(home, dst, ignore)
    (dst / 'Lib/site-packages').mkdir(parents=True, exist_ok=True)


def copy_env(env):
    src = ROOT / f'experiments/{env}/.venv'
    dst = OUT / f'experiments/{env}/.venv'
    say(f'Copying environment {env} ...')
    (dst / 'Scripts').mkdir(parents=True, exist_ok=True)
    for exe in ('python.exe', 'pythonw.exe'):
        shutil.copy2(src / 'Scripts' / exe, dst / 'Scripts' / exe)
    site = src / 'Lib/site-packages'
    out = dst / 'Lib/site-packages'
    out.mkdir(parents=True, exist_ok=True)
    for item in site.iterdir():
        name = item.name.lower()
        base = dist_name(item.name) if name.endswith(('.dist-info', '.egg-info')) else name.split('.')[0]
        if base in SKIP_PACKAGES or name.startswith('__editable__') or name == '__pycache__':
            continue
        if item.is_dir() and item.name == 'PySide6':
            copy_qt(item, out / 'PySide6')
        elif item.is_dir():
            copy_tree(item, out / item.name, ignore_libs)
        else:
            shutil.copy2(item, out / item.name)
    if env == 'speakeasy':
        # Defender flags Speakeasy's 32-bit decoy program as a trojan (false positive); MLWINT never uses it
        decoy = out / 'speakeasy/winenv/decoys/x86'
        shutil.rmtree(decoy, ignore_errors=True)


def copy_qt(src, dst):
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        if item.is_file() and QT_KEEP_FILES.match(item.name):
            shutil.copy2(item, dst / item.name)
        elif item.is_dir() and item.name in QT_KEEP_DIRS:
            copy_tree(item, dst / item.name)
        elif item.is_dir() and item.name == 'plugins':
            for plug in item.iterdir():
                if plug.name in QT_KEEP_PLUGINS:
                    copy_tree(plug, dst / 'plugins' / plug.name)


def copy_mlwint():
    say('Copying MLWINT itself ...')
    copy_tree(APP_BUILD, OUT / 'app')
    for name in ('mlwint_engine.py', 'mlwint_analyse.py', 'mlwint_report.py'):
        if (ROOT / 'scripts' / name).is_file():
            (OUT / 'scripts').mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / 'scripts' / name, OUT / 'scripts' / name)
    copy_tree(ROOT / 'src', OUT / 'src')
    copy_tree(ROOT / 'models', OUT / 'models')
    (OUT / 'data/attack').mkdir(parents=True, exist_ok=True)
    for f in (ROOT / 'data/attack').glob('*.json'):
        shutil.copy2(f, OUT / 'data/attack' / f.name)
    for part in ('rules', 'sigs'):
        copy_tree(ROOT / CAPA_SOURCE / part, OUT / CAPA_SOURCE / part)
    (OUT / 'experiments/speakeasy/decoys-x86-empty').mkdir(parents=True, exist_ok=True)
    for empty in ('config', 'reports'):
        (OUT / empty).mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / 'version.json', OUT / 'version.json')


def write_venv_cfgs(install_dir, version):
    """pyvenv.cfg for each environment, pointing at install_dir/runtime/python (the installer does the same)."""
    for env in ENVS:
        cfg = install_dir / f'experiments/{env}/.venv/pyvenv.cfg'
        cfg.write_text(f'home = {install_dir / "runtime/python"}\ninclude-system-site-packages = false\n'
                       f'version = {version}\n', encoding='utf-8')


def python_version(home):
    out = subprocess.run([str(home / 'python.exe'), '-c', 'import platform; print(platform.python_version())'],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def check_bundle():
    """Starts the bundled engine, asks for its health check and quits: proves the bundle runs on its own."""
    say('Checking the bundle ...')
    py = OUT / 'experiments/ember2024/.venv/Scripts/python.exe'
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(('PYTHON', 'MLWINT_'))}
    p = subprocess.run([str(py), '-u', str(OUT / 'scripts/mlwint_engine.py')], input='{"id":1,"cmd":"health"}\n',
                       capture_output=True, text=True, encoding='utf-8', cwd=str(OUT), env=env, timeout=600)
    reply = next((json.loads(line) for line in p.stdout.splitlines() if line.startswith('{"id": 1')), None)
    if not reply or not reply.get('ok'):
        say(p.stdout[-2000:], p.stderr[-3000:])
        raise SystemExit('BUNDLE CHECK FAILED')
    bad = [h['part'] for h in reply['data'] if not h['ok'] and 'keys' not in h['part'].lower()]
    for h in reply['data']:
        say(f'  {"OK " if h["ok"] else "-- "} {h["part"]}')
    if bad:
        raise SystemExit('BUNDLE CHECK FAILED: missing ' + ', '.join(bad))


def build_installer(v):
    iscc = shutil.which('ISCC') or next((str(p) for p in (
        Path(os.environ.get('LOCALAPPDATA', '')) / 'Programs/Inno Setup 6/ISCC.exe',
        Path(os.environ.get('ProgramFiles(x86)', '')) / 'Inno Setup 6/ISCC.exe',
        Path(os.environ.get('ProgramFiles', '')) / 'Inno Setup 6/ISCC.exe') if p.is_file()), None)
    if not iscc:
        say('Inno Setup (ISCC.exe) not found: the bundle in dist/MLWINT is ready, the installer was skipped.')
        return None
    say('Building the installer ...')
    subprocess.run([iscc, f'/DAppVersion={v["app"]}', f'/DModelsVersion={v["models"]}',
                    f'/DPyVersion={v["python"]}', str(ROOT / 'packaging/mlwint.iss')], check=True)
    setup = DIST / f'MLWINT-Setup-{v["app"]}.exe'
    say(f'Installer: {setup} ({mb(setup.stat().st_size)})')
    return setup


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--skip-flutter', action='store_true', help='reuse the last Flutter build')
    ap.add_argument('--no-installer', action='store_true', help='only build dist/MLWINT')
    a = ap.parse_args()
    t = time.time()
    v = versions()
    home = base_python()
    v['python'] = python_version(home)
    say(f'MLWINT {v["app"]} (models {v["models"]}, Python {v["python"]})')
    if not a.skip_flutter:
        build_flutter(v['app'])
    if not (APP_BUILD / 'MLWINT.exe').is_file():
        raise SystemExit(f'no Flutter build in {APP_BUILD}: run without --skip-flutter')
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    copy_runtime(home)
    for env in ENVS:
        copy_env(env)
    copy_mlwint()
    write_venv_cfgs(OUT, v['python'])
    check_bundle()
    say(f'Bundle: {OUT} ({mb(size_of(OUT))})')
    if not a.no_installer:
        build_installer(v)
    say(f'RELEASE_BUILT in {time.time() - t:.0f} s')


if __name__ == '__main__':
    main()
