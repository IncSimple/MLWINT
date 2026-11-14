"""MLWINT Phase 3 step 3.4: advice engine (read-only). Save as MLWINT/src/detection/phase3_advice.py

Turns one analysis result (threat score + evidence + behaviour tags + emulation + "on this PC" facts) into a short,
ordered list of things YOU can do, each with the reason that triggered it. MLWINT itself never deletes, quarantines,
stops, uninstalls or changes anything: every action is written for a person to carry out.

Order of actions:  1 = now (stop harm)   2 = clean up   3 = protect accounts / data   4 = check / optional
Main rules:
  * the advice depends on what has HAPPENED on this PC: "downloaded, never run" -> do not run it, delete it yourself;
    "running" / "starts automatically" / "was run" -> disconnect, end it, remove the startup entry, offline scan
  * account / data steps (passwords, backups) only when the file was run (or might have been) AND its behaviour
    calls for them (stealer, keylogger, banker, ransomware ...)
  * PDFs: phishing-style without active content -> link / sender advice only; with JavaScript / embedded files ->
    open safely or not at all
  * an alarm that rests on the detector alone, or a file signed by a known publisher, is said to possibly be a false
    alarm: the user is told how to confirm
"""
from urllib.parse import urlsplit

STEALING = {'stealer', 'passwordstealer', 'spyware', 'banker'}
STEALING_ATTACK = {'T1555', 'T1056.001', 'T1113', 'T1003', 'T1539', 'T1552'}
RANSOM = {'ransom', 'cryptor', 'killfiles', 'blocker'}
RANSOM_ATTACK = {'T1486', 'T1490', 'T1485'}
REMOTE = {'backdoor', 'remoteshell'}
SPREAD = {'worm', 'virus', 'infector', 'autorun'}
FETCH = {'downloader', 'dropper'}
PDF_ACTIVE = {'/JavaScript', '/JS', '/Launch', '/EmbeddedFile', '/RichMedia', '/XFA', '#xx-escaped names'}
UNWANTED = {'adware', 'pua', 'riskware', 'gamehack'}
OFFLINE_SCAN = ('Run a Microsoft Defender Offline scan: Windows Security > Virus & threat protection > Scan options > '
                'Microsoft Defender Offline scan > Scan now (the PC restarts and scans before Windows loads)')
STARTUP_HOWTO = {
    'Run': 'Task Manager > Startup apps > right-click the entry > Disable (or delete the value "{name}" in regedit '
           'under {where})',
    'scheduled task': 'Task Scheduler > Task Scheduler Library > find "{name}" > right-click > Disable, then Delete',
    'service': 'services.msc > "{name}" > Stop, then Startup type: Disabled (only for a service you do not recognise)',
    'Startup folder': 'delete the item "{name}" from the Startup folder (Win+R > shell:startup)',
    'Winlogon': 'this changes how Windows logs on: get help from someone experienced, a wrong change can stop '
                'Windows from starting ({where} {name})',
    'Image File Execution Options': 'regedit > {where}\\{name} > delete the "Debugger" value',
}


def act(priority, text, because, aid):
    return dict(priority=priority, action=text, because=because, id=aid)


def startup_howto(entry):
    where = entry['where']
    key = next((k for k in STARTUP_HOWTO if k.lower() in where.lower()), None) or 'Run'
    return STARTUP_HOWTO[key].format(name=entry.get('name'), where=where)


def advise(r):
    """r: one mlwint_analyse result. Returns dict(headline, actions, notes)."""
    if r.get('status') != 'assessed':
        return dict(headline='not analysed', actions=[], notes=[r.get('reason') or ''])
    level, verdict, fmt = r['level'], r['verdict'], r['format']
    ctx = r.get('local_context') or {}
    tags = {b['tag'] for b in r.get('behaviours', [])}
    attack = {t['id'] for t in r.get('attack', [])}
    deep = r.get('deep_check') or {}
    deep_titles = [f['title'] for f in deep.get('findings', [])] if deep.get('status') == 'completed' else []
    sig = r.get('signature') or {}
    signer = (sig.get('signer') or '').split(',')[0].replace('CN=', '').strip('"') if sig.get('status') == 'Valid' else None
    origin = ctx.get('origin') or {}
    site = origin.get('site') or (origin.get('referrer') and urlsplit(origin['referrer']).netloc) or None
    running = ctx.get('running') or []
    autostart = ctx.get('autostart') or []
    ran = ctx.get('ran_before') or {}
    ran_record = bool(ran.get('compatibility_assistant') or ran.get('userassist'))
    has_run = bool(running or autostart or ran_record)
    unknown = not ctx                                   # 'on this PC' checks not run: it may have been run
    defender = ctx.get('defender') or []
    actions, notes = [], []
    detector_only = not tags and not deep_titles and not any(
        p['part'] in ('evidence', 'outside opinion') and p['points'] > 0 for p in r.get('parts', []))
    outside = next((p for p in r.get('parts', []) if p['part'] == 'outside opinion'), None)

    if origin:
        notes.append(f'came from {site or origin.get("zone_name")}')
    if outside:
        notes.append(f'outside opinion (hash lookup): {outside["reason"]}')
    if defender:
        d = defender[0]
        notes.append(f'Microsoft Defender already detected it as {d["threat"]} on {d["time"][:10]}')
        actions.append(act(4, 'Open Windows Security > Virus & threat protection > Protection history and check what '
                              'Defender did with it', f'Defender detected it as {d["threat"]}', 'defender_history'))

    # ---------------------------------------------------------------- LOW
    if level == 'LOW':
        return dict(headline='No action needed', actions=actions, notes=notes)

    # ---------------------------------------------------------------- PDF
    if fmt == 'PDF':
        active = r.get('pdf_active_content')
        if active is None:                              # older reports: use the PDF check's findings
            active = sorted(set((r.get('evidence') or {}).get('pdf_findings') or []) & PDF_ACTIVE)
        if not active:
            headline = 'Probably harmless to open - be careful with its links'
            actions.append(act(3, 'Do not click links or fill in forms in this PDF unless you expected it' +
                               (f' from {site}' if site else '') + '; if it asks you to log in or pay, go to the '
                               'website yourself instead of using the link',
                               'the detector finds it similar to phishing documents, but it contains nothing that '
                               'can run', 'pdf_links'))
            if site:
                notes.append(f'downloaded from {site}: if that is the official site you expected, this is very '
                             'likely a false alarm')
        else:
            headline = 'Do not open this PDF normally' if level in ('HIGH', 'SEVERE') else 'Open this PDF with care'
            if any(a in active for a in ('/JavaScript', '/JS')):
                actions.append(act(1 if level in ('HIGH', 'SEVERE') else 2,
                                   'If you must open it, turn off JavaScript in your PDF reader first (Adobe Reader: '
                                   'Edit > Preferences > JavaScript > untick "Enable Acrobat JavaScript") or open it '
                                   'in a browser viewer instead', 'it contains JavaScript', 'pdf_js'))
            if '/EmbeddedFile' in active:
                actions.append(act(2, 'Do not open files attached inside this PDF', 'it carries an embedded file',
                                   'pdf_embedded'))
            if '/Launch' in active:
                actions.append(act(1, 'Do not allow it to launch anything if your reader asks',
                                   'it contains a launch action', 'pdf_launch'))
            if level in ('HIGH', 'SEVERE'):
                actions.append(act(2, 'If you do not need it, delete it yourself', f'threat level {level}',
                                   'delete_file'))
        return dict(headline=headline, actions=sorted(actions, key=lambda a: a['priority']), notes=notes)

    # ---------------------------------------------------------------- programs
    serious = level in ('ELEVATED', 'HIGH', 'SEVERE')
    if level == 'GUARDED':
        headline = 'Only run it if you trust where it came from'
        actions.append(act(3, 'Run it only if you know and trust its source' + (f' ({site})' if site else ''),
                           'some weak warning signs', 'trust_source'))
        if tags & UNWANTED:
            actions.append(act(3, 'If you install it, choose "Custom install" and untick any extra offers, toolbars '
                                  'or browser changes', f'tagged as {", ".join(sorted(tags & UNWANTED))}', 'custom_install'))
        if not has_run:
            actions.append(act(4, 'If you do not need it, delete it yourself', 'nothing shows it has been run',
                               'delete_file'))
    elif unknown:
        headline = 'Do not run it - and scan the PC in case it was run'
        actions.append(act(1, 'Do not open or run this file', f'threat level {level}', 'do_not_run'))
        actions.append(act(2, OFFLINE_SCAN, 'MLWINT did not check whether it has been run on this PC', 'offline_scan'))
        actions.append(act(2, 'Delete it yourself (select it, Shift+Delete)', f'threat level {level}', 'delete_file'))
    elif not has_run:
        headline = 'Do not run it - delete it yourself'
        actions.append(act(1, 'Do not open or run this file', f'threat level {level}', 'do_not_run'))
        actions.append(act(2, 'Delete it yourself (select it, Shift+Delete), and empty it from the Recycle Bin if '
                              'you used normal Delete', 'nothing shows it has been run, so deleting it ends the risk',
                           'delete_file'))
        actions.append(act(4, 'Optionally get a second opinion: right-click the file > Scan with Microsoft Defender',
                           'MLWINT is one opinion', 'defender_scan_file'))
    else:
        headline = 'It may be active on this PC - act now'
        if running:
            actions.append(act(1, 'Disconnect this PC from the internet (Wi-Fi off / unplug the cable)',
                               'it is running right now', 'disconnect'))
            actions.append(act(1, 'End it: Task Manager > Details > ' + ', '.join(f'{p["name"]} (PID {p["pid"]})'
                                                                                  for p in running) + ' > End task',
                               'it is running right now', 'end_process'))
        for e in autostart:
            actions.append(act(2, 'Remove the startup entry: ' + startup_howto(e),
                               f'it is set to start automatically ({e["where"]})', 'remove_startup'))
        actions.append(act(2, OFFLINE_SCAN, 'it has run on this PC' + (' and may have hidden itself' if level in
                                                                       ('HIGH', 'SEVERE') else ''), 'offline_scan'))
        actions.append(act(2, 'After the scan, delete the file yourself if it is still there', f'threat level {level}',
                           'delete_file'))
        last = (ran.get('userassist') or {}).get('last_run')
        if last:
            notes.append(f'last started from Explorer on {last}')

    if serious:
        maybe_ran = has_run or unknown
        if (tags & STEALING or attack & STEALING_ATTACK) and maybe_ran:
            actions.append(act(3, 'From another, clean device: change the passwords you used on this PC (email first, '
                                  'then banking and shopping), turn on two-step verification, and sign out of other '
                                  'sessions', 'it can steal passwords or watch what you type: '
                               + ', '.join(sorted((tags & STEALING) | (attack & STEALING_ATTACK))), 'change_passwords'))
            if 'banker' in tags:
                actions.append(act(3, 'Check your bank statements and tell your bank if you see anything unusual',
                                   'tagged as a banking trojan', 'check_bank'))
        if (tags & RANSOM or attack & RANSOM_ATTACK) and maybe_ran:
            actions.append(act(1, 'Unplug external backup drives and do not connect them until the PC is clean; do '
                                  'not pay any ransom', 'ransomware-like behaviour: '
                               + ', '.join(sorted((tags & RANSOM) | (attack & RANSOM_ATTACK))), 'protect_backups'))
        if (tags & REMOTE or 'T1055' in attack) and maybe_ran and level in ('HIGH', 'SEVERE'):
            actions.append(act(3, 'Because someone may have had remote control, consider resetting Windows (Settings > '
                                  'System > Recovery) after backing up your documents, and change your passwords',
                               'backdoor / remote-control behaviour', 'consider_reset'))
        if tags & SPREAD and maybe_ran:
            actions.append(act(3, 'Scan USB drives and other PCs this one shares files with',
                               'it can spread: ' + ', '.join(sorted(tags & SPREAD)), 'scan_other_devices'))
        if tags & FETCH and maybe_ran:
            notes.append('it downloads or unpacks more malware, so other harmful files may be on this PC: the offline '
                         'scan matters')
        if 'coinminer' in tags and maybe_ran:
            actions.append(act(4, 'Watch for high CPU / fan use in Task Manager after cleaning',
                               'tagged as a cryptocurrency miner', 'check_cpu'))
        if tags & UNWANTED and maybe_ran and not tags - UNWANTED - {'packed'}:
            actions.append(act(2, 'Uninstall it: Settings > Apps > Installed apps, and reset your browser settings '
                                  'if they changed', f'tagged as {", ".join(sorted(tags & UNWANTED))}', 'uninstall'))
        servers = (deep.get('observed') or {}).get('servers') or []
        if servers:
            notes.append('it tries to contact: ' + ', '.join(servers[:6]))

    if signer and level != 'LOW':
        notes.append(f'it carries a valid signature from "{signer}": if that is the publisher you meant to get it from, '
                     'this may be a false alarm - check the download page is the publisher\'s own site')
    if detector_only and level != 'LOW':
        notes.append('this warning rests on the machine-learning detector alone (no supporting evidence was found): '
                     'false alarms happen, so confirm with a Defender scan before deleting anything important')
    if unknown and serious:
        notes.append('the "on this PC" checks were not run, so the advice assumes the file may have been run')
    notes.append('MLWINT never deletes or changes anything: these steps are for you to carry out')
    seen, ordered = set(), []
    for a in sorted(actions, key=lambda a: a['priority']):
        if a['id'] not in seen or a['id'] == 'remove_startup':
            seen.add(a['id'])
            ordered.append(a)
    return dict(headline=headline, actions=ordered, notes=notes)


def advice_text(advice):
    lines = [f'  ADVICE: {advice["headline"]}']
    for i, a in enumerate(advice['actions'], 1):
        lines.append(f'    {i}. [{ {1: "now", 2: "clean up", 3: "protect", 4: "check"}[a["priority"]] }] {a["action"]}')
        lines.append(f'       because {a["because"]}')
    for n in advice['notes'][:-1]:
        lines.append(f'    note: {n}')
    return '\n'.join(lines)