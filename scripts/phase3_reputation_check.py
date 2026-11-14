"""Step 3.3 check of the hash lookup. Save as MLWINT/scripts/phase3_reputation_check.py
Run from the MLWINT folder with the EMBER2024 environment:
    experiments/ember2024/.venv/Scripts/python.exe scripts/phase3_reputation_check.py            (offline only)
    experiments/ember2024/.venv/Scripts/python.exe scripts/phase3_reputation_check.py --live     (also 1 real lookup)

  1. which keys are set (shown masked) and what the cache holds
  2. OFFLINE self-test with made-up service replies (nothing is sent): found / not found / 45 of 70 engines /
     0 of 70 engines / errors; checks the points, that a second lookup comes from the cache, and that every request
     carries ONLY the SHA-256 (no file name, path or file content)
  3. --live: one real lookup of the public EICAR anti-virus test file's hash (a harmless standard test string that
     every antivirus detects; its hash is public). Uses your keys; sends only that hash.
Writes only reports/phase3/reputation-check-v1.json (and the real cache for --live).
"""
import argparse, json, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import src.detection.phase3_reputation as rep  # noqa: E402

EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
SHA_A, SHA_B, SHA_C = 'a' * 64, 'b' * 64, 'c' * 64
TEST_PATH = r'C:\Users\someone\Downloads\secret-name.exe'


def fake_service(sent):
    """Pretend MalwareBazaar / VirusTotal: SHA_A is known malware, SHA_B is clean and common, SHA_C is unknown."""
    def http(req):
        body = (req.data or b'').decode()
        sent.append(dict(url=req.full_url, body=body, headers=dict(req.header_items())))
        if 'abuse.ch' in req.full_url:
            if SHA_A in body:
                return 200, dict(query_status='ok', data=[dict(sha256_hash=SHA_A, signature='AgentTesla',
                                                               file_type='exe', first_seen='2026-01-01', tags=['x'])])
            return 200, dict(query_status='hash_not_found')
        if req.full_url.endswith(SHA_A):
            return 200, dict(data=dict(attributes=dict(last_analysis_stats=dict(malicious=45, suspicious=1,
                                                                                undetected=24, harmless=0),
                                                       popular_threat_classification=dict(
                                                           suggested_threat_label='trojan.agenttesla/msil'))))
        if req.full_url.endswith(SHA_B):
            return 200, dict(data=dict(attributes=dict(last_analysis_stats=dict(malicious=0, suspicious=0,
                                                                                undetected=65, harmless=5))))
        return 404, dict(error=dict(code='NotFoundError'))
    return http


def meter_result(level='GUARDED', fmt='PDF', points=39.0, cap=39.0, floor=20):
    return dict(status='assessed', path=TEST_PATH, format=fmt, verdict='MALICIOUS', level=level, score=int(points),
                floor=floor, cap=cap, parts=[dict(part='detector', points=points, reason='x')])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--live', action='store_true')
    a = ap.parse_args()
    keys = rep.load_keys()
    print('1. Keys: ' + (', '.join(f'{k} ({v[:4]}...{v[-2:]})' for k, v in keys.items()) or
                         'none set (lookups stay off; the offline self-test still runs)'))
    if rep.CACHE.is_file():
        c = json.loads(rep.CACHE.read_text(encoding='utf-8'))
        print(f'   cache: {len(c.get("hashes", {}))} hashes, {len(c.get("sent_log", []))} lookups logged')

    print('2. Offline self-test (made-up replies, nothing leaves the PC):')
    ok, sent = True, []
    rep.VT_GAP = 0
    with tempfile.TemporaryDirectory() as tmp:
        r = rep.Reputation(keys=dict(malwarebazaar='test-key', virustotal='test-key'),
                           cache_path=Path(tmp) / 'cache.json', http_fn=fake_service(sent))
        checks = []
        res_a = r.lookup(SHA_A)
        pts, floor, why = rep.opinion(res_a)
        checks.append(('known malware: +40, floor 60', pts == 40 and floor == 60, why))
        lifted = rep.add_to_meter(meter_result(), res_a)
        checks.append(('known malware lifts the PDF cap to HIGH or above', lifted['score'] >= 60
                       and lifted['level'] in ('HIGH', 'SEVERE'), f'score {lifted["score"]} {lifted["level"]}'))
        res_b = r.lookup(SHA_B)
        pts, floor, why = rep.opinion(res_b)
        checks.append(('widely seen, 0 of 70 engines: -10', pts == -10 and floor is None, why))
        res_c = r.lookup(SHA_C)
        pts, floor, why = rep.opinion(res_c)
        checks.append(('unknown everywhere: 0 points, "not a clean bill"', pts == 0 and 'not a clean bill' in why, why))
        before = len(sent)
        again = r.lookup(SHA_A)
        checks.append(('second lookup comes from the cache', len(sent) == before and all(v.get('cached') for v in
                                                                                         again.values()), ''))
        leaked = [s for s in sent if 'secret-name' in s['url'] + s['body'] or 'Downloads' in s['url'] + s['body']]
        only_hash = all(set(s['body'].split('&')) <= {'query=get_info', f'hash={SHA_A}', f'hash={SHA_B}',
                                                      f'hash={SHA_C}'} for s in sent if s['body'])
        checks.append(('requests carry only the SHA-256', not leaked and only_hash, f'{len(sent)} requests'))
        bad = rep.Reputation(keys=dict(malwarebazaar='k'), cache_path=Path(tmp) / 'c2.json',
                             http_fn=lambda req: (_ for _ in ()).throw(OSError('no internet')))
        pts, floor, why = rep.opinion(bad.lookup(SHA_A))
        checks.append(('no internet: reported, 0 points, nothing crashes', pts == 0 and 'no internet' in why, why))
        for name, passed, detail in checks:
            ok &= bool(passed)
            print(f'   {"PASS" if passed else "FAIL"}  {name:<52} {detail[:90]}')

    live = None
    if a.live:
        print('3. Live lookup of the EICAR test file hash (only this hash is sent):')
        if not keys:
            print('   no keys set - skipped')
        else:
            live = rep.Reputation().lookup(EICAR_SHA256)
            for s, v in live.items():
                print(f'   {s}: {v}')
            print('   meter: ' + rep.opinion(live)[2])
    status = 'PHASE3_STEP3_CHECKED' if ok else 'PHASE3_STEP3_FAILED'
    out = ROOT / 'reports/phase3/reputation-check-v1.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(status=status, keys=sorted(keys), live=live), indent=1), encoding='utf-8')
    print(f'\n{status}: {out}')


if __name__ == '__main__':
    main()