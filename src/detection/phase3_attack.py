"""MLWINT Phase 3 step 3.2: offline MITRE ATT&CK knowledge (read-only). Save as MLWINT/src/detection/phase3_attack.py

Reads MITRE's official ATT&CK Enterprise data (STIX 2.1 JSON, downloaded once to MLWINT/data/attack/) and explains
every technique MLWINT reports: name, tactic(s), a short plain description, MITRE's mitigations (with how they
apply to this technique) and how defenders detect it. No internet connection is used during a scan.
  * revoked technique ids (older capa rules may still use them) are followed to their replacement
  * deprecated techniques are flagged
  * the first load builds a small index next to the data (attack-index.json, keyed by the data file's SHA-256),
    later loads take well under a second
"""
import hashlib, json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'data/attack/enterprise-attack.json'
INDEX_VERSION = 1
CITATION = re.compile(r'\s*\(Citation:[^)]*\)')
MDLINK = re.compile(r'\[([^\]]+)\]\([^)]+\)')
CODE = re.compile(r'<code>(.*?)</code>')


def tidy(text):
    """ATT&CK descriptions use markdown, <code> and (Citation: ...) markers: plain text for the report."""
    text = CITATION.sub('', text or '')
    text = MDLINK.sub(r'\1', text)
    text = CODE.sub(r'\1', text)
    return re.sub(r'\s+', ' ', text).strip()


def first_sentences(text, n=2, limit=400):
    parts = re.split(r'(?<=[.!?])\s+(?=[A-Z])', tidy(text))
    out = ' '.join(parts[:n])
    return out if len(out) <= limit else out[:limit].rsplit(' ', 1)[0] + ' ...'


def mitre_id(obj):
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack' and ref.get('external_id'):
            return ref['external_id'], ref.get('url')
    return None, None


def build_index(objects):
    by_stix = {o['id']: o for o in objects if 'id' in o}
    tactics = {o.get('x_mitre_shortname'): o.get('name') for o in objects if o.get('type') == 'x-mitre-tactic'}
    version = next((o.get('x_mitre_version') for o in objects if o.get('type') == 'x-mitre-collection'), None)
    techniques, stix_to_tid, revoked = {}, {}, {}
    for o in objects:
        if o.get('type') != 'attack-pattern':
            continue
        tid, url = mitre_id(o)
        if not tid:
            continue
        stix_to_tid[o['id']] = tid
        if o.get('revoked'):
            revoked[tid] = o['id']
            continue
        techniques[tid] = dict(
            id=tid, name=o.get('name'), url=url,
            tactics=[tactics.get(k['phase_name'], k['phase_name']) for k in o.get('kill_chain_phases', [])
                     if k.get('kill_chain_name') == 'mitre-attack'],
            platforms=o.get('x_mitre_platforms', []), deprecated=bool(o.get('x_mitre_deprecated')),
            summary=first_sentences(o.get('description')),
            detection_text=first_sentences(o.get('x_mitre_detection'), 2) if o.get('x_mitre_detection') else None,
            mitigations=[], detected_by=[])
    revoked_by = {}
    for r in objects:
        if r.get('type') != 'relationship' or r.get('revoked') or r.get('x_mitre_deprecated'):
            continue
        kind, src, dst = r.get('relationship_type'), by_stix.get(r.get('source_ref')), r.get('target_ref')
        tid = stix_to_tid.get(dst)
        if kind == 'revoked-by':
            old = stix_to_tid.get(r.get('source_ref'))
            if old and tid:
                revoked_by[old] = tid
        elif kind == 'mitigates' and tid in techniques and src and src.get('type') == 'course-of-action' \
                and not src.get('x_mitre_deprecated') and not src.get('revoked'):
            mid, murl = mitre_id(src)
            techniques[tid]['mitigations'].append(dict(id=mid, name=src.get('name'), url=murl,
                                                       how=first_sentences(r.get('description'), 1, 260)))
        elif kind == 'detects' and tid in techniques and src:
            name = src.get('name')
            if name and name not in techniques[tid]['detected_by']:
                techniques[tid]['detected_by'].append(name)
    for t in techniques.values():
        t['mitigations'].sort(key=lambda m: m['id'] or '')
        t['detected_by'] = sorted(t['detected_by'])[:8]
    for tid in revoked:                                       # revoked without a 'revoked-by' link: keep a note
        revoked_by.setdefault(tid, None)
    return dict(index_version=INDEX_VERSION, attack_version=version, techniques=techniques, revoked_by=revoked_by,
                tactics=sorted(set(tactics.values())))


class AttackKnowledge:
    def __init__(self, path=None):
        self.path = Path(path) if path else DATA
        if not self.path.is_file():
            raise FileNotFoundError(f'ATT&CK data not found: {self.path} (download enterprise-attack.json first)')
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        cache = self.path.with_name('attack-index.json')
        idx = None
        if cache.is_file():
            try:
                idx = json.loads(cache.read_text(encoding='utf-8'))
                if idx.get('source_sha256') != digest or idx.get('index_version') != INDEX_VERSION:
                    idx = None
            except ValueError:
                idx = None
        if idx is None:
            bundle = json.loads(self.path.read_text(encoding='utf-8'))
            idx = build_index(bundle.get('objects', []))
            idx['source_sha256'] = digest
            idx['source_file'] = self.path.name
            cache.write_text(json.dumps(idx), encoding='utf-8')
        self.index = idx
        self.version = idx.get('attack_version')
        self.sha256 = digest

    def explain(self, tid):
        """Explanation for one technique id (T1055, T1547.001, ...); follows revoked ids to their replacement."""
        t = self.index['techniques'].get(tid)
        note = None
        if t is None and tid in self.index['revoked_by']:
            new = self.index['revoked_by'][tid]
            t = self.index['techniques'].get(new) if new else None
            note = f'{tid} was replaced by {new} in ATT&CK' if new else f'{tid} was withdrawn from ATT&CK'
        if t is None and '.' in tid:                           # unknown sub-technique: explain its parent
            parent = self.index['techniques'].get(tid.split('.')[0])
            if parent:
                t, note = parent, f'{tid} is not in ATT&CK v{self.version}; showing its parent technique'
        if t is None:
            return dict(id=tid, found=False, note=f'{tid} is not in ATT&CK v{self.version}')
        out = dict(t, found=True, asked=tid, note=note or ('deprecated in ATT&CK' if t['deprecated'] else None))
        if '.' in t['id']:
            parent = self.index['techniques'].get(t['id'].split('.')[0])
            out['parent'] = parent['name'] if parent else None
        return out

    def short(self, tid, mitigations=3):
        """One readable line for reports."""
        e = self.explain(tid)
        if not e['found']:
            return f'{tid}: {e["note"]}'
        name = f'{e["parent"]}: {e["name"]}' if e.get('parent') else e['name']
        line = f'{e["id"]} {name} ({", ".join(e["tactics"])}) - {e["summary"]}'
        if e['mitigations']:
            line += ' | MITRE mitigations: ' + '; '.join(f'{m["id"]} {m["name"]}' for m in e['mitigations'][:mitigations])
        if e.get('note'):
            line += f' [{e["note"]}]'
        return line