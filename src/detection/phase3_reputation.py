"""MLWINT Phase 3 step 3.3: outside opinion by file hash (OPT-IN). Save as MLWINT/src/detection/phase3_reputation.py

Asks threat-intelligence services whether they already know a file - by its SHA-256 fingerprint ONLY.
The file itself, its name, its path and anything about this PC are never sent. Off unless you switch it on
(mlwint_analyse --reputation flagged|all) AND have put in your own free API key(s):
  MalwareBazaar (abuse.ch)  - a database of malware samples: "known" means somebody shared it as malware
  VirusTotal (optional)     - results of ~70 antivirus engines for files others uploaded (free key: 4 lookups/min,
                              500/day; free keys are for personal, non-commercial use)
Keys: environment variables MLWINT_MALWAREBAZAAR_KEY / MLWINT_VIRUSTOTAL_KEY, or MLWINT/config/intel_keys.json
      {"malwarebazaar": "...", "virustotal": "..."}   (keep that file private; never commit it)
Every lookup is stored in reports/intel/hash-cache.json (answer + what was sent, to whom, when), so the same hash is
not sent twice: answers are reused for 7 days ("not found" for 1 day).
How it counts in the threat meter (part 'outside opinion', written reasons, like every other part):
  MalwareBazaar knows it as malware            +20, and the score is at least 60 (HIGH), also for PDFs
  VirusTotal: >= 10 engines say malicious      +20, at least 60      3-9 engines: +10      1-2 engines: +3 (noise)
  VirusTotal: 0 of >= 50 engines flag it        -10 (widely seen, nobody flags it)
  not known anywhere                             0 (new or rare files are often unknown: this is NOT a clean bill)
"""
import json, os, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / 'reports/intel/hash-cache.json'
KEYS_FILE = ROOT / 'config/intel_keys.json'
MB_URL = 'https://mb-api.abuse.ch/api/v1/'
VT_URL = 'https://www.virustotal.com/api/v3/files/'
FOUND_DAYS, NOT_FOUND_DAYS = 7, 1
VT_GAP = 15.5                     # seconds between VirusTotal lookups (free key: 4 per minute)
VT_DAILY = 500
USER_AGENT = 'MLWINT-hash-lookup/1.0'


def load_keys():
    keys = {}
    if KEYS_FILE.is_file():
        try:
            keys = {k: v for k, v in json.loads(KEYS_FILE.read_text(encoding='utf-8')).items() if v}
        except ValueError:
            pass
    for name, env in (('malwarebazaar', 'MLWINT_MALWAREBAZAAR_KEY'), ('virustotal', 'MLWINT_VIRUSTOTAL_KEY')):
        if os.environ.get(env):
            keys[name] = os.environ[env]
    return keys


def http(request, timeout=20):
    """One HTTPS request -> (status code, parsed JSON or None). Separate function so tests can replace it."""
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8', 'replace') or 'null')
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode('utf-8', 'replace') or 'null')
        except ValueError:
            body = None
        return e.code, body


class Reputation:
    def __init__(self, keys=None, cache_path=None, http_fn=None):
        self.keys = load_keys() if keys is None else keys
        self.cache_path = Path(cache_path) if cache_path else CACHE
        self.http = http_fn or http
        self.cache = self._load()
        self._last_vt = 0.0

    def _load(self):
        if self.cache_path.is_file():
            try:
                return json.loads(self.cache_path.read_text(encoding='utf-8'))
            except ValueError:
                pass
        return dict(hashes={}, sent_log=[], vt_daily={})

    def _save(self):
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache_path.with_name(self.cache_path.name + '.pending')
        tmp.write_text(json.dumps(self.cache, indent=1), encoding='utf-8')
        tmp.replace(self.cache_path)

    @property
    def sources(self):
        return [s for s in ('malwarebazaar', 'virustotal') if self.keys.get(s)]

    # ---------------- one service each
    def _malwarebazaar(self, sha):
        body = urllib.parse.urlencode(dict(query='get_info', hash=sha)).encode()
        req = urllib.request.Request(MB_URL, data=body, method='POST',
                                     headers={'Auth-Key': self.keys['malwarebazaar'], 'User-Agent': USER_AGENT})
        code, data = self.http(req)
        status = (data or {}).get('query_status')
        if code == 200 and status == 'ok' and data.get('data'):
            d = data['data'][0]
            return dict(status='found', malicious=True, family=d.get('signature'), file_type=d.get('file_type'),
                        first_seen=d.get('first_seen'), tags=(d.get('tags') or [])[:8],
                        link=f'https://bazaar.abuse.ch/sample/{sha}/')
        if code == 200 and status in ('hash_not_found', 'no_results'):
            return dict(status='not_found')
        return dict(status='error', reason=f'HTTP {code}, {status or "no answer"}')

    def _virustotal(self, sha):
        today = time.strftime('%Y-%m-%d')
        used = self.cache['vt_daily'].get(today, 0)
        if used >= VT_DAILY:
            return dict(status='skipped', reason=f'daily VirusTotal limit ({VT_DAILY}) reached')
        wait = VT_GAP - (time.time() - self._last_vt)
        if wait > 0:
            time.sleep(wait)
        req = urllib.request.Request(VT_URL + sha, headers={'x-apikey': self.keys['virustotal'],
                                                            'User-Agent': USER_AGENT})
        code, data = self.http(req)
        self._last_vt = time.time()
        self.cache['vt_daily'] = {today: used + 1}
        if code == 200 and data and data.get('data'):
            a = data['data'].get('attributes', {})
            stats = a.get('last_analysis_stats', {})
            engines = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
            label = (a.get('popular_threat_classification') or {}).get('suggested_threat_label')
            return dict(status='found', malicious_engines=int(stats.get('malicious', 0)),
                        suspicious_engines=int(stats.get('suspicious', 0)), engines=engines, label=label,
                        first_seen=a.get('first_submission_date'), link=f'https://www.virustotal.com/gui/file/{sha}')
        if code == 404:
            return dict(status='not_found')
        if code == 429:
            return dict(status='error', reason='VirusTotal quota exceeded (HTTP 429)')
        return dict(status='error', reason=f'HTTP {code}')

    # ---------------- public
    def lookup(self, sha):
        sha = sha.lower()
        out, now = {}, time.time()
        entry = self.cache['hashes'].setdefault(sha, {})
        for source in self.sources:
            old = entry.get(source)
            if old and old['result']['status'] in ('found', 'not_found'):
                days = FOUND_DAYS if old['result']['status'] == 'found' else NOT_FOUND_DAYS
                if now - old['checked'] < days * 86400:
                    out[source] = dict(old['result'], cached=True)
                    continue
            try:
                res = self._malwarebazaar(sha) if source == 'malwarebazaar' else self._virustotal(sha)
            except (OSError, ValueError) as e:                     # offline, timeout, bad answer
                res = dict(status='error', reason=f'{type(e).__name__}: {e}'[:200])
            self.cache['sent_log'].append(dict(time=time.strftime('%Y-%m-%d %H:%M:%S'), to=source, sent=sha))
            if res['status'] in ('found', 'not_found'):
                entry[source] = dict(result=res, checked=now)
            out[source] = res
        self.cache['sent_log'] = self.cache['sent_log'][-5000:]
        self._save()
        return out


def opinion(results):
    """(points, floor or None, reason text) from lookup() results."""
    pts, floor, why = 0.0, None, []
    mb, vt = results.get('malwarebazaar'), results.get('virustotal')
    if mb and mb['status'] == 'found':
        pts += 20
        floor = 60
        why.append('MalwareBazaar knows this exact file as malware' + (f' ({mb["family"]})' if mb.get('family') else ''))
    elif mb and mb['status'] == 'not_found':
        why.append('not in MalwareBazaar')
    if vt and vt['status'] == 'found':
        m, n = vt['malicious_engines'], vt['engines']
        label = f', "{vt["label"]}"' if vt.get('label') else ''
        if m >= 10:
            pts += 20
            floor = 60
            why.append(f'VirusTotal: {m} of {n} engines say malicious{label}')
        elif m >= 3:
            pts += 10
            why.append(f'VirusTotal: {m} of {n} engines say malicious{label}')
        elif m >= 1:
            pts += 3
            why.append(f'VirusTotal: only {m} of {n} engines flag it (often noise)')
        elif n >= 50:
            pts -= 10
            why.append(f'VirusTotal: none of {n} engines flags it')
        else:
            why.append(f'VirusTotal: 0 of {n} engines flag it')
    elif vt and vt['status'] == 'not_found':
        why.append('not known to VirusTotal')
    errors = [f'{s}: {r.get("reason")}' for s, r in results.items() if r['status'] in ('error', 'skipped')]
    why += errors
    if results and all(r['status'] == 'not_found' for r in results.values()):
        why.append('unknown files are common (new or rare): this is not a clean bill of health')
    return pts, floor, '; '.join(why) or 'no lookup made'


def add_to_meter(r, results):
    """Adds the 'outside opinion' part to a ThreatMeter / analyse result and recomputes score + level."""
    from .phase2_meter import level
    pts, floor, why = opinion(results)
    r = dict(r, parts=[p for p in r['parts'] if p['part'] != 'outside opinion'], reputation=results)
    r['parts'].append(dict(part='outside opinion', points=pts, reason=why))
    lo = max(r.get('floor', 0), floor or 0)
    hi = 100.0 if floor else r.get('cap', 100.0)            # known malware lifts the PDF cap
    r['score'] = int(round(max(lo, min(hi, 100.0, sum(p['points'] for p in r['parts'])))))
    r['level'] = level(r['score'])
    if floor:
        r['floor'], r['cap'] = lo, 100.0
    return r