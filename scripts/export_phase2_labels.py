"""MLWINT Phase 2 step 2.2a: export the EMBER2024 malware labels (family, behaviour, ...) for Colab.
Save as MLWINT/scripts/export_phase2_labels.py and run from the MLWINT folder:
    experiments/ember2024/.venv/Scripts/python.exe scripts/export_phase2_labels.py all
    (or one format: win32 | win64 | dotnet | pdf)

The Phase 1 shards on Drive already hold the leakage-checked splits (fit 0-35 / stop 36-39 / dev 40-51 /
test 52-63) and every row's SHA-256. This script only adds the labels: it reads the original weekly EMBER2024
files you already have (data/raw/ember2024/archives) and keeps, for each unique MALICIOUS file:
    week, family, family_confidence, behavior, file_property, packer, exploit, group, detection_ratio,
    ttps (ATT&CK ids from EMBER's own capa run), mbc ids
Colab joins these to the shards by SHA-256, so the time split and leakage rules stay exactly as in Phase 1.
Rules:
  * every file is listed twice in EMBER2024 (one copy with EMBER's capa results, one without): both copies must
    carry the same labels (else stop); the copy with the capa results is kept
  * test weeks 52-63 are exported but NOT summarised or printed (they stay sealed for the final check)
Resumes safely (each finished week is kept). Writes only exports/colab/labels-v1. Archives are only read.
"""
import argparse, gzip, hashlib, json, os, re, sys, time, zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_DIR = ROOT / 'data/raw/ember2024/archives'
FORMATS = {'win32': 'Win32', 'win64': 'Win64', 'dotnet': 'Dot_Net', 'pdf': 'PDF'}
KEEP = ('family', 'family_confidence', 'behavior', 'file_property', 'packer', 'exploit', 'group', 'detection_ratio')
TECH = re.compile(r'\[(T\d{4}(?:\.\d{3})?)\]')
MBC = re.compile(r'\[([A-Z]\d{4}(?:\.[A-Za-z0-9]+)?)\]')
SEALED_FROM = 52


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def replace(src, dst):
    for _ in range(120):                       # Defender / indexer can lock a new file for a moment
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            time.sleep(0.5)
    os.replace(src, dst)


def label_row(r):
    row = dict(sha256=r['sha256'], week=r['week_id'], **{k: r.get(k) for k in KEEP})
    row['ttps'] = sorted({m for t in (r.get('ttps') or []) for m in TECH.findall(str(t.get('Technique', '')))})
    row['mbc'] = sorted({m for b in (r.get('mbc') or []) for m in MBC.findall(str(b.get('Behavior', '')))})
    row['capa_rules'] = len(r.get('caps') or [])
    return row


def export_week(archive, member, week, file_type, target):
    rows, stats = {}, Counter()       # the two copies of a file differ only in EMBER's capa results
    with archive.open(member) as stream:
        for line in stream:
            r = json.loads(line)
            stats['records'] += 1
            if r['file_type'] != file_type or r['week_id'] != week:
                raise ValueError(f'{member}: unexpected file type / week in record {stats["records"]}')
            if r['label'] != 1:
                continue
            row = label_row(r)
            old = rows.get(row['sha256'])
            if old is not None:
                if any(old[k] != row[k] for k in ('week', *KEEP)):
                    raise ValueError(f'{member}: the same file has different labels: {row["sha256"]}')
                stats['repeated'] += 1
                if row['capa_rules'] > old['capa_rules']:          # keep the copy that has the capa results
                    rows[row['sha256']] = row
                continue
            rows[row['sha256']] = row
    rows = list(rows.values())
    tmp = target.with_name(target.name + '.pending')
    with gzip.open(tmp, 'wt', encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps(row, separators=(',', ':')) + '\n')
    replace(tmp, target)
    return dict(file=target.name, rows=len(rows), records_read=stats['records'], repeated=stats['repeated'],
                sha256=sha256(target), bytes=target.stat().st_size)


def summarise(folder, weeks):
    """Weeks 0-51 only (test stays sealed)."""
    fam_fit, fam_all, beh, prop, n, no_family = Counter(), Counter(), Counter(), Counter(), 0, 0
    for w in weeks:
        if w['week'] >= SEALED_FROM:
            continue
        with gzip.open(folder / w['file'], 'rt', encoding='utf-8') as f:
            for line in f:
                r = json.loads(line)
                n += 1
                if r['family']:
                    fam_all[r['family']] += 1
                    if r['week'] < 40:
                        fam_fit[r['family']] += 1
                else:
                    no_family += 1
                beh.update(r['behavior'] or ['(none)'])
                prop.update(f'{k}:{v}' for k in ('file_property', 'packer', 'exploit', 'group') for v in (r[k] or []))
    return dict(malicious_files_weeks_0_51=n, with_family=n - no_family,
                family_coverage=round((n - no_family) / max(n, 1), 4), families=len(fam_all),
                families_with_50_plus_in_weeks_0_39=sum(c >= 50 for c in fam_fit.values()),
                files_covered_by_those=sum(c for c in fam_fit.values() if c >= 50),
                top_families=fam_all.most_common(15), behaviours=beh.most_common(25),
                top_properties=prop.most_common(15),
                test_weeks='sealed: exported, not summarised')


def export_format(key, out):
    name = FORMATS[key]
    folder = out / key
    folder.mkdir(parents=True, exist_ok=True)
    state_path = folder / 'state.json'
    state = json.loads(state_path.read_text()) if state_path.exists() else dict(format=key, weeks=[])
    done = {w['week'] for w in state['weeks']}
    for w in state['weeks']:                                   # finished weeks must still be intact
        if sha256(folder / w['file']) != w['sha256']:
            raise ValueError(f'{folder / w["file"]} changed since it was written; delete it and rerun.')
    for part, first, count in (('train', 0, 52), ('test', 52, 12)):
        path = ARCHIVE_DIR / f'{name}_{part}.zip'
        if not path.is_file():
            raise SystemExit(f'Missing archive {path}')
        with zipfile.ZipFile(path) as archive:
            members = sorted(m for m in archive.namelist() if m.endswith(f'_{name}_{part}.jsonl'))
            if len(members) != count:
                raise ValueError(f'{path.name}: expected {count} weekly files, found {len(members)}')
            for i, member in enumerate(members):
                week = first + i
                if week in done:
                    continue
                t0 = time.time()
                info = export_week(archive, member, week, name, folder / f'week_{week:02d}.jsonl.gz')
                state['weeks'].append(dict(week=week, source=f'{path.name}:{member}', **info))
                state['weeks'].sort(key=lambda w: w['week'])
                tmp = state_path.with_name('state.json.pending')
                tmp.write_text(json.dumps(state, indent=1))
                replace(tmp, state_path)
                shown = f'{info["rows"]:,} malware files' if week < SEALED_FROM else 'test week (sealed)'
                print(f'  {key} week {week:02d}: {shown}; {time.time() - t0:.0f} s', flush=True)
    if [w['week'] for w in state['weeks']] != list(range(64)):
        raise ValueError(f'{key}: not all 64 weeks exported')
    state['summary'] = summarise(folder, state['weeks'])
    state['status'] = 'complete'
    tmp = state_path.with_name('state.json.pending')
    tmp.write_text(json.dumps(state, indent=1))
    replace(tmp, state_path)
    return state


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('format', choices=[*FORMATS, 'all'])
    ap.add_argument('--out', type=Path, default=ROOT / 'exports/colab/labels-v1')
    a = ap.parse_args()
    keys = list(FORMATS) if a.format == 'all' else [a.format]
    a.out.mkdir(parents=True, exist_ok=True)
    manifest_path = a.out / 'manifest.json'
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else dict(formats={})
    for key in keys:
        print(f'\n{key}: reading {FORMATS[key]}_train.zip + {FORMATS[key]}_test.zip ...', flush=True)
        state = export_format(key, a.out)
        s = state['summary']
        print(f'\n{key.upper()} weeks 0-51: {s["malicious_files_weeks_0_51"]:,} malware files, family known for '
              f'{s["family_coverage"]:.1%}; {s["families"]} families, {s["families_with_50_plus_in_weeks_0_39"]} with '
              f'50+ training files (covering {s["files_covered_by_those"]:,})')
        print('  top families : ' + ', '.join(f'{f} {c}' for f, c in s['top_families'][:10]))
        print('  behaviours   : ' + ', '.join(f'{b} {c}' for b, c in s['behaviours'][:12]))
        print('  properties   : ' + ', '.join(f'{p} {c}' for p, c in s['top_properties'][:8]))
        manifest['formats'][key] = dict(
            weeks={str(w['week']): dict(file=f'{key}/{w["file"]}', rows=w['rows'], sha256=w['sha256'])
                   for w in state['weeks']},
            summary=s)
    manifest['status'] = 'PHASE2_LABELS_READY' if all(k in manifest['formats'] for k in FORMATS) else 'PARTIAL'
    manifest['note'] = ('Labels of malicious files only, one row per SHA-256; join to the Phase 1 shards by SHA-256. '
                        'Weeks 52-63 are the sealed test.')
    tmp = manifest_path.with_name('manifest.json.pending')
    tmp.write_text(json.dumps(manifest, indent=1))
    replace(tmp, manifest_path)
    size = sum(p.stat().st_size for p in a.out.rglob('*.jsonl.gz')) / 1024**2
    print(f'\n{manifest["status"]}: {a.out} ({size:.0f} MB). '
          + ('Upload this folder to Google Drive -> MLWINT-colab/inputs/labels-v1' if manifest['status'] ==
             'PHASE2_LABELS_READY' else 'Run the remaining formats (or "all").'))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nStopped. Rerun the same command to resume.')