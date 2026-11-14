# Security and responsible use

MLWINT is a **defensive, read-only** analysis tool. It never executes, deletes, moves, quarantines or uploads
the files it checks.

## Handling malware
- MLWINT's checks are static analysis and **emulation** (Speakeasy interprets instructions in a model of
  Windows; nothing really runs). Even so, do not keep or open real malware on a normal workstation. Use an
  isolated virtual machine for samples.
- **Never upload malware**, private documents, API keys or identifying file details to issues or pull requests.
  Share hashes and anonymised report excerpts instead.

## Keys and privacy
- Hash lookup is **off by default**. With your own MalwareBazaar / VirusTotal keys it sends only SHA-256
  fingerprints. Keys are stored locally in `config/intel_keys.json`, which is git-ignored and never included in
  the installer. Do not commit it.

## Models
- Load only models from this repository's Releases (checksums are in `SHA256SUMS.txt` and the detector cards).
  Model files are loaded by XGBoost/LightGBM native loaders, but treat any model from an unknown source as code.

## Verdicts
- A score is evidence, not proof. False alarms and misses are expected (see the README's Results and
  Limitations). MLWINT's advice is guidance; the user decides.

## Reporting a vulnerability
Please use GitHub's **private vulnerability reporting** for this repository (Security tab → Report a
vulnerability) rather than a public issue. Include the MLWINT version (Help → About) and steps to reproduce.
