"""MLWINT Phase 2 step 2.3: transparent 0-100 threat meter (read-only).
Save as MLWINT/src/detection/phase2_meter.py

Every point on the meter has a written reason. Five parts, added up and kept between 0 and 100:
  1. detector   0-60  Phase 1 verdict and probability (CLEAN 0-15, SUSPICIOUS 15-40, MALICIOUS 40-60)
  2. behaviour  0-25  behaviour tags (backdoor, ransom, ...) - only when Phase 1 says SUSPICIOUS or MALICIOUS,
                      because these models were trained on malware only and say nothing about clean files
  3. evidence   0-15  what the file CAN do: capa ATT&CK tactics (programs) or risky PDF elements;
                      halved for CLEAN files (clean files have these too: notepad shows 11 techniques)
  4. family     0-5   a named malware family (only above its frozen 90%-precision threshold)
  5. context  -15..+5 valid digital signature lowers the score (only -5 for MALICIOUS: signed malware exists),
                      Downloads/Temp/AppData/Desktop raises it
Floors: MALICIOUS never shows below 40, SUSPICIOUS never below 20.
Reliability of every tag / family comes from the sealed TEST (weeks 52-63), fixed rule, not tuned:
  test precision >= 90% strong ("behaves like"), 80-90% normal ("likely"), 70-80% hint ("possibly"), < 70% hidden.
  Family names are shown only for formats whose test precision when naming is >= 85% (PDF families are hidden).
"""
import hashlib, json, os, subprocess
from pathlib import Path

import numpy as np

from .phase1_detectors import FORMAT_NAMES, MAX_BYTES, Phase1Detectors, detect_format

ROOT = Path(__file__).resolve().parents[2]
LEVELS = [(80, 'SEVERE'), (60, 'HIGH'), (40, 'ELEVATED'), (20, 'GUARDED'), (0, 'LOW')]
TIERS = [(0.90, 'strong', 1.0, 'behaves like'), (0.80, 'normal', 0.7, 'likely'), (0.70, 'hint', 0.35, 'possibly')]
FAMILY_MIN_TEST_PRECISION = 0.85
TAG_SEVERITY = {   # 3 = directly harmful, 2 = delivers / hides / abuses, 1 = unwanted or a property
    **dict.fromkeys(('ransom', 'backdoor', 'remoteshell', 'banker', 'stealer', 'passwordstealer', 'spyware',
                     'killfiles', 'blocker', 'worm', 'virus', 'infector', 'ddos', 'webshell', 'exploit', 'ircbot'), 3),
    **dict.fromkeys(('downloader', 'dropper', 'injector', 'coinminer', 'hacktool', 'proxy', 'phishing', 'autorun',
                     'servstart', 'selfdel', 'selfmod', 'encoder'), 2),
    **dict.fromkeys(('adware', 'pua', 'riskware', 'gamehack', 'packed', 'cryptor'), 1),
}
TAG_TEXT = {'ransom': 'ransomware (encrypts or locks files for money)', 'backdoor': 'a backdoor (remote control)',
            'remoteshell': 'a remote shell', 'banker': 'a banking trojan', 'stealer': 'an information stealer',
            'passwordstealer': 'a password stealer', 'spyware': 'spyware', 'killfiles': 'destroys files',
            'blocker': 'a screen / system blocker', 'worm': 'a worm (spreads by itself)',
            'virus': 'a file-infecting virus', 'ddos': 'a DDoS bot', 'webshell': 'a web shell',
            'exploit': 'an exploit document', 'downloader': 'a downloader (fetches more malware)',
            'dropper': 'a dropper (unpacks more malware)', 'injector': 'injects code into other programs',
            'coinminer': 'a cryptocurrency miner', 'hacktool': 'a hacking tool', 'proxy': 'a proxy bot',
            'phishing': 'a phishing document', 'autorun': 'spreads via autorun', 'servstart': 'installs a service',
            'selfdel': 'deletes itself after running', 'selfmod': 'modifies itself', 'encoder': 'encodes its payload',
            'adware': 'adware', 'pua': 'a potentially unwanted application', 'riskware': 'riskware',
            'gamehack': 'a game hack / cheat', 'packed': 'packed (its code is compressed or hidden)',
            'cryptor': 'wrapped in a crypter'}
TACTIC_WEIGHT = {'Impact': 4, 'Credential Access': 4, 'Command and Control': 3, 'Exfiltration': 3,
                 'Lateral Movement': 3, 'Persistence': 3, 'Privilege Escalation': 3, 'Defense Evasion': 2,
                 'Collection': 2, 'Initial Access': 2, 'Execution': 1, 'Discovery': 1}
PDF_ACTIVE = {'/JavaScript', '/JS', '/Launch', '/EmbeddedFile', '/RichMedia', '/XFA', '#xx-escaped names'}
PDF_CAP = 39.0
RISKY_FOLDERS = ('downloads', 'temp', 'tmp', 'appdata', 'desktop', 'inetcache', 'content.outlook')

def _sha(data):
    return hashlib.sha256(data).hexdigest()


def level(score):
    return next(name for low, name in LEVELS if score >= low)


def tier(precision):
    for low, name, factor, words in TIERS:
        if precision is not None and precision >= low:
            return name, factor, words
    return 'hidden', 0.0, None


def signature(path):
    """Windows Authenticode status (embedded or catalog signature), via PowerShell. Read-only."""
    if os.name != 'nt':
        return dict(status='unknown')
    p = str(path).replace("'", "''")
    cmd = (f"$s = Get-AuthenticodeSignature -LiteralPath '{p}'; "
           "[string]$s.Status + '|' + [string]$s.SignerCertificate.Subject")
    try:
        r = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', cmd], capture_output=True,
                           text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
        status, _, subject = r.stdout.strip().partition('|')
        return dict(status=status or 'unknown', signer=subject or None)
    except (OSError, subprocess.SubprocessError):
        return dict(status='unknown')


class Phase2Classifiers:
    def __init__(self, bundle_dir=None, verify=True):
        self.dir = Path(bundle_dir) if bundle_dir else ROOT / 'models/phase2'
        self.manifest = json.loads((self.dir / 'manifest.json').read_text())
        if self.manifest.get('status') != 'MLWINT_PHASE2_BUNDLE':
            raise ValueError(f'{self.dir} is not an MLWINT Phase 2 bundle')
        if verify:
            for name, info in self.manifest['files'].items():
                if hashlib.sha256((self.dir / name).read_bytes()).hexdigest() != info['sha256']:
                    raise ValueError(f'Checksum failed: {name}. Unpack the bundle again.')
        self.cards, self.reports, self._boosters = {}, {}, {}
        for key in self.manifest['formats']:
            self.cards[key] = json.loads((self.dir / key / 'card.json').read_text())
            self.reports[key] = json.loads((self.dir / key / 'test_report.json').read_text())

    def booster(self, key, name):
        if (key, name) not in self._boosters:
            import xgboost as xgb
            b = xgb.Booster(model_file=str(self.dir / key / name))
            b.set_param({'device': 'cpu', 'nthread': 4})
            self._boosters[key, name] = b
        return self._boosters[key, name]

    def family_probabilities(self, key, X):
        return np.asarray(self.booster(key, self.cards[key]['family']['model']).inplace_predict(X), np.float64)

    def tag_probability(self, key, tag, X):
        return np.asarray(self.booster(key, self.cards[key]['behaviour'][tag]['model']).inplace_predict(X), np.float64)

    def describe(self, key, x):
        """Family + behaviour tags for ONE feature vector of a file Phase 1 flagged."""
        X = np.ascontiguousarray(x, dtype=np.float32).reshape(1, -1)
        card, report = self.cards[key], self.reports[key]
        out = dict(family=None, family_note=None, tags=[])
        fam = card['family']
        if fam.get('model'):
            P = self.family_probabilities(key, X)[0]
            classes, other = fam['classes'], len(fam['classes']) - 1
            best = int(np.argmax(P[:other]))
            test_precision = report.get('family', {}).get('precision_when_named')
            if test_precision is None or test_precision < FAMILY_MIN_TEST_PRECISION:
                out['family_note'] = (f'family names are not shown for {FORMAT_NAMES[key]} files (only '
                                      f'{test_precision:.0%} right on the test weeks)' if test_precision is not None
                                      else 'no test result for the family model')
            elif P[best] >= fam['threshold']:
                out['family'] = dict(name=classes[best], confidence=round(float(P[best]), 4),
                                     test_precision=test_precision)
            else:
                out['family_note'] = 'family not identified with enough confidence'
        for tag, v in card['behaviour'].items():
            if not v.get('model'):
                continue
            p = float(self.tag_probability(key, tag, X)[0])
            if p < v['threshold']:
                continue
            test_precision = report.get('behaviour', {}).get(tag, {}).get('precision')
            name, factor, words = tier(test_precision)
            out['tags'].append(dict(tag=tag, probability=round(p, 4), tier=name, weight=factor, words=words,
                                    test_precision=test_precision, severity=TAG_SEVERITY.get(tag, 2)))
        out['tags'].sort(key=lambda t: (-t['weight'] * t['severity'], t['tag']))
        return out


class ThreatMeter:
    def __init__(self, phase1_dir=None, phase2_dir=None, verify=True):
        self.detectors = Phase1Detectors(phase1_dir, verify=verify)
        self.classifiers = Phase2Classifiers(phase2_dir, verify=verify)

    def assess(self, path, evidence=None, check_signature=True):
        """evidence: optional result of phase2_evidence.evidence_for_file for the same file (capa / PDF check)."""
        path = Path(path)
        try:
            if path.stat().st_size > MAX_BYTES:
                return dict(path=str(path), status='skipped', reason=f'larger than {MAX_BYTES // 1024**2} MB')
            with open(path, 'rb') as f:                                    # read-only
                data = f.read()
        except OSError as e:
            return dict(path=str(path), status='skipped', reason=f'cannot read: {e.strerror or e}')
        digest = _sha(data)
        key, reason = detect_format(data)
        if key is None or key not in self.detectors.cards:
            return dict(path=str(path), sha256=digest, status='unsupported', reason=reason)
        x = np.asarray(self.detectors.extractor().feature_vector(data), dtype=np.float32)
        if x.shape != (2568,) or not np.isfinite(x).all():
            return dict(path=str(path), sha256=digest, status='failed', reason='feature extraction failed')
        p = float(self.detectors.probability(key, x)[0])
        verdict = self.detectors.verdict(key, p)
        thr = self.detectors.cards[key]['verdicts']
        t_sus, t_mal = thr['suspicious']['threshold'], thr['malicious']['threshold']
        parts = []

        # 1. detector
        if verdict == 'MALICIOUS':
            pts = 40 + 20 * (p - t_mal) / max(1 - t_mal, 1e-9)
        elif verdict == 'SUSPICIOUS':
            pts = 15 + 25 * (p - t_sus) / max(t_mal - t_sus, 1e-9)
        else:
            pts = 15 * p / max(t_sus, 1e-9)
        parts.append(dict(part='detector', points=round(pts, 1),
                          reason=f'{FORMAT_NAMES[key]} detector says {verdict} (malware probability {p:.3f}; '
                                 f'suspicious from {t_sus:.3f}, malicious from {t_mal:.3f})'))

        # 2. behaviour + 4. family (malware-only models)
        described = None
        if verdict != 'CLEAN' and key in self.classifiers.cards:
            described = self.classifiers.describe(key, x)
            shown = [t for t in described['tags'] if t['tier'] != 'hidden']
            pts = min(25.0, sum(4 * t['severity'] * t['weight'] for t in shown))
            text = '; '.join(f'{t["words"]} {TAG_TEXT.get(t["tag"], t["tag"])} '
                             f'(right {t["test_precision"]:.0%} of the time on test)' for t in shown)
            parts.append(dict(part='behaviour', points=round(pts, 1),
                              reason=text or 'no behaviour recognised (this does not mean harmless)'))
            fam = described['family']
            parts.append(dict(part='family', points=5.0 if fam else 0.0,
                              reason=f'matches the {fam["name"]} malware family (confidence {fam["confidence"]:.0%})'
                              if fam else described['family_note']))
        else:
            parts.append(dict(part='behaviour', points=0.0,
                              reason='not checked: behaviour and family models only describe files the detector flags'))

                # 3. evidence
        if key == 'pdf' and not (evidence and evidence.get('sha256') == digest):
            from .phase2_evidence import pdf_indicators                  # fast, so PDFs always get it
            evidence = dict(status='analysed', sha256=digest, evidence=pdf_indicators(data))
        pdf_active = None
        ev_inner = (evidence or {}).get('evidence') or {}
        if evidence and evidence.get('status') == 'analysed' and evidence.get('sha256') == digest \
                and ev_inner.get('status') != 'completed':
            parts.append(dict(part='evidence', points=0.0,
                              reason=f'capability check {ev_inner.get("status", "failed")} '
                                     f'({str(ev_inner.get("reason", ""))[:120]}) - capabilities unknown, not "none"'))
        elif evidence and evidence.get('status') == 'analysed' and evidence.get('sha256') == digest:
            factor = 0.5 if verdict == 'CLEAN' else 1.0
            if key == 'pdf':
                findings = ev_inner.get('findings', [])
                raw = sum(2 * f['risk'] for f in findings)
                what = ', '.join(f['indicator'] for f in findings) or 'no risky elements'
                pdf_active = sorted({f['indicator'] for f in findings} & PDF_ACTIVE)
            else:
                tactics = evidence.get('attack_tactics', {})
                raw = sum(TACTIC_WEIGHT.get(t, 1) for t in tactics)
                what = (f'{len(evidence.get("attack_techniques", []))} ATT&CK techniques in tactics '
                        + ', '.join(tactics)) if tactics else 'no ATT&CK capabilities found'
            pts = min(15.0, raw) * factor
            parts.append(dict(part='evidence', points=round(pts, 1),
                              reason=what + (' (halved: the detector says CLEAN, and clean files have these '
                                             'too)' if factor < 1 and raw else '')))
        else:
            parts.append(dict(part='evidence', points=0.0, reason='capability check not run for this file'))

        # 5. context
        pts, notes = 0.0, []
        sig = signature(path) if check_signature and key != 'pdf' else dict(status='not checked')
        if sig['status'] == 'Valid':
            pts -= 5 if verdict == 'MALICIOUS' else 15     # stolen / abused certificates exist: small effect then
            notes.append(f'valid digital signature ({sig.get("signer") or "unknown signer"})'
                         + (' - but signed malware exists, so it counts only a little here'
                            if verdict == 'MALICIOUS' else ''))
        elif sig['status'] in ('HashMismatch', 'NotTrusted'):
            pts += 5
            notes.append(f'digital signature is {sig["status"]} (broken or untrusted)')
        folders = [s.lower() for s in path.resolve().parts]
        if any(f in RISKY_FOLDERS for f in folders):
            pts += 5
            notes.append('stored in a download / temporary / user-profile folder')
        pts = max(-15.0, min(5.0, pts))
        parts.append(dict(part='context', points=pts, reason='; '.join(notes) or 'nothing notable'))

                # PDF rule: without active content the detector alone cannot go above GUARDED (real-world documents with
        # links look like EMBER's phishing PDFs; a PDF with nothing that can run is low risk to open)
        floor = 40 if verdict == 'MALICIOUS' else 20 if verdict == 'SUSPICIOUS' else 0
        cap = 100.0
        if key == 'pdf' and pdf_active is not None and not pdf_active and verdict != 'CLEAN':
            floor, cap = min(floor, 20), PDF_CAP
            total = sum(pt['points'] for pt in parts)
            if total > cap:
                parts.append(dict(part='pdf rule', points=round(cap - total, 1),
                                  reason=f'no active content (no JavaScript, launch action, embedded file, rich media '
                                         f'or disguised names): capped at {PDF_CAP:.0f}. It may be a phishing-style '
                                         f'document - opening it is low risk, but do not trust its links'))
        score = int(round(max(floor, min(cap, 100.0, sum(pt['points'] for pt in parts)))))
        return dict(path=str(path), sha256=digest, status='assessed', format=FORMAT_NAMES[key], format_reason=reason,
                    verdict=verdict, probability=p, score=score, level=level(score), parts=parts,
                    floor=floor, cap=cap, pdf_active_content=pdf_active,
                    family=described['family'] if described else None,
                    behaviours=[t for t in described['tags'] if t['tier'] != 'hidden'] if described else [],
                    hidden_behaviours=[t['tag'] for t in described['tags'] if t['tier'] == 'hidden'] if described
                    else [], signature=sig,
                    note='The meter explains risk; it never deletes, moves or uploads anything.')


def explain(r):
    """Plain-language text for one assess() result."""
    if r['status'] != 'assessed':
        return f'{r["path"]}: {r["status"]} ({r.get("reason")})'
    lines = [f'{r["path"]}', f'  THREAT {r["score"]}/100  {r["level"]}   ({r["format"]}, detector {r["verdict"]})']
    for pt in r['parts']:
        lines.append(f'  {pt["points"]:+6.1f}  {pt["part"]:<9} {pt["reason"]}')
    return '\n'.join(lines)