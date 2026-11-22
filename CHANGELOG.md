# Changelog

## 4.0.0 - 2026-11-22

### Added
- Pattern-aware password analysis: repeated characters/chunks, ascending/descending
  sequences, keyboard walks (rows and columns), embedded years, and
  leetspeak-normalized dictionary detection, with a 0-4 score.
- Three crack-time scenarios: online rate-limited, offline slow hash (bcrypt),
  offline fast hash (GPU).
- Passphrase generator (`-pp`) using the embedded 1296-word EFF short list.
- Hidden password input: `mrpass -ps` prompts without echo, or reads from a pipe,
  keeping secrets out of shell history.
- Password masking in all output, JSON and CSV exports; no password-derived
  hashes are stored (unsalted digests would be offline verification material).
- Hash identifier expanded to 25 formats with hashcat `-m` / John `--format` hints.
- Email analysis: syntax validation (local), MX lookup via DNS-over-HTTPS,
  disposable detection (local list + debounce.io), fixed XposedOrNot parsing.
- Phone analysis: line type, E.164/international/national formats,
  possible-vs-valid distinction.
- Wordlist mutator: multiple base words, `--years` ranges, `--level` 1-3,
  `--no-leet`, `--min`/`--max` length bounds, deterministic deduped output.
- `--json` machine-readable output, `--no-color`/`NO_COLOR`, `--no-symbols`,
  `--separator`, `--version`.
- Real exit codes: 0 success, 1 usage error, 2 bad arguments.
- 71-test suite (66 offline + 5 opt-in live API checks), GitHub Actions CI
  (Python 3.9-3.13), MIT LICENSE, pyproject
  packaging (`pip install .` / `pipx`), root-free `install.sh`, CHANGELOG.

### Fixed
- Generator hung forever on lengths under 4 (`-n 3`).
- argparse errors were swallowed and exited 0.
- Passwords were echoed in plaintext to the terminal and CSV exports.
- XposedOrNot nested breach list was displayed incorrectly.
- All network failures were hidden by bare `except: pass`; each lookup now
  reports a specific error.
- Keyboard-walk detection is linear (the naive scan stalled on long bulk lines).
- CSV exports neutralize spreadsheet formula injection in every cell.
- A failed CSV export (e.g. unwritable path) now exits 1.

### Changed
- Online lookups stay opt-in via `-sr`; local analysis never touches the network.
- Installer no longer requires sudo or global pip installs.
