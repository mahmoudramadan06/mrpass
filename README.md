<div align="center">

```text
    ____ ___  _________  ____  ____ _____
   / __ `__ \/ ___/ __ \/ __ \/ ___/ ___/
  / / / / / / /  / /_/ / /_/ (__  |__  )
 /_/ /_/ /_/_/  / .___/\__,_/____/____/
               /_/
```

### Advanced OSINT & Security Analysis CLI — v4.0.0

**Password strength auditing, breach intelligence, phone/email OSINT, hash identification and authorized-audit wordlist generation. Free and open source (MIT).**

</div>

---

## What's new in v4.0.0

- **Pattern-aware strength analysis:** detects repeated characters/chunks, sequences (`abcd`, `4321`), keyboard walks (`qwerty`, `1qaz`), embedded years, and leetspeak-normalized dictionary passwords (`P@ssw0rd` is caught), with three realistic crack-time scenarios instead of one naive estimate.
- **Privacy-first password handling:** passwords are masked in every display, JSON result and CSV export, no password-derived hash is ever stored (an unsalted digest would be offline verification material), and input can be piped via stdin or typed into a hidden prompt instead of appearing in shell history.
- **Passphrase generator:** memorable passphrases from the embedded 1296-word EFF short list, plus CSPRNG passwords with `--no-symbols` and fixed handling of short lengths (v3 hung forever on `-n 3`).
- **25-format hash identifier:** bcrypt, Argon2, md5crypt/sha256crypt/sha512crypt, phpass, Drupal, Django PBKDF2, LDAP schemes, Kerberos, MySQL, JWT and more, with hashcat `-m` and John `--format` hints.
- **Smarter email OSINT:** syntax validation (local), MX lookup over DNS-over-HTTPS, disposable detection (local list + debounce.io), XposedOrNot breach check with fixed response parsing.
- **Richer phone analysis:** line type (mobile/VoIP/fixed), E.164/international/national formats, possible-vs-valid distinction, carrier, country and timezones.
- **Rebuilt wordlist mutator:** multiple base words, year ranges (`--years 2018-2026`), three intensity levels, leetspeak toggle, length bounds, deterministic deduped output.
- **Scriptable:** `--json` machine-readable output, real exit codes (0 ok, 1 usage, 2 bad arguments), `--no-color`/`NO_COLOR` support, masked CSV export.
- **Quality:** 71-test suite (66 offline + 5 opt-in live API checks via `python -m unittest discover -s tests`), MIT LICENSE file, proper packaging (`pip install .` / `pipx`), root-free installer.

## Install

```bash
git clone https://github.com/mahmoudramadan06/mrpass.git
cd mrpass

# Option 1: pipx (recommended)
pipx install .

# Option 2: installer script (venv in ~/.local/share, no sudo)
./install.sh

# Option 3: plain pip
pip install .
```

Then run `mrpass -h` from anywhere. Requires Python 3.9+.

## Usage

```text
mrpass [TARGET] [OPTIONS]
```

### Target modes

| Flag | Description |
|---|---|
| `-ps`, `--password` | Password strength, pattern findings, crack-time scenarios |
| `-em`, `--email` | Email syntax, breaches, disposable and MX checks |
| `-ph`, `--phone` | Phone validation, carrier, country, line type, OSINT dorks |
| `-id`, `--identify` | Identify hash types (25+ formats, hashcat/john hints) |
| `-m`, `--mutate [FILE]` | Audit wordlist from base words (authorized use only) |
| `-n`, `--new [LENGTH]` | Generate a CSPRNG password (default: 16) |
| `-pp`, `--passphrase [N]` | Generate a passphrase (default: 5 words) |

### Options

| Flag | Description |
|---|---|
| `-sr`, `--search-leak` | Opt-in online lookups (see Privacy below) |
| `-f`, `--file FILE` | Bulk mode: read targets from a text file |
| `-o`, `--output FILE` | Export results to CSV (secrets masked) |
| `-q`, `--quiet` | One-line output per target |
| `--json` | Machine-readable JSON output |
| `--no-color` | Disable ANSI colors (NO_COLOR env also works) |
| `--no-symbols` | Generate alphanumeric-only passwords |
| `--separator SEP` | Passphrase word separator (default `-`) |
| `--years A-B` | Mutator year suffixes (default: current year) |
| `--level 1-3` | Mutator intensity (default: 2) |
| `--no-leet` | Disable leetspeak mutations |
| `--min N`, `--max N` | Mutator length bounds |
| `--version` | Print version |

## Examples

```bash
# Hidden prompt (no shell-history leak), local analysis only
mrpass -ps

# Same + HaveIBeenPwned breach check (k-anonymity; password never sent)
mrpass -ps -sr

# Pipe a password from a password manager
pass show email | mrpass -ps -sr

# Email: syntax (local), then opt-in breach/disposable/MX checks
mrpass "user@mail.com" -em -sr

# Phone OSINT (fully local, no network)
mrpass "+2010xxxxxxxx" -ph

# Identify a hash
mrpass "\$2y\$10\$N9qo8uLOickgx2ZMRZoMye..." -id

# Generate
mrpass -n 20
mrpass -pp 6 --separator .

# Audit wordlist (authorized use only)
mrpass "company,petname" -m wordlist.txt --years 2020-2026 --level 2

# Bulk scan with masked CSV export and JSON summary
mrpass -f targets.txt -ps -sr -o report.csv --json
```

## Privacy

Local analysis (strength, patterns, hash ID, phone metadata, email syntax, generation, wordlists) **never leaves your machine**. Online lookups run only with `-sr`:

| Check | Service | What is sent |
|---|---|---|
| Password breach | HaveIBeenPwned range API | First 5 hex chars of the SHA-1 hash (k-anonymity). The password itself is never sent. |
| Email breach | XposedOrNot | The email address |
| Disposable check | debounce.io | The email address |
| MX lookup | Cloudflare/Google DNS-over-HTTPS | The email's domain |

Passwords are never printed in full and no unsalted password-derived hash is ever shown or stored: output and CSV exports carry only the masked form.

## Responsible use

The wordlist mutator and OSINT dorks are for **authorized security auditing of your own credentials and systems** (the same scope as tools like cupp and crunch). Don't use them against accounts, people or systems you don't own or lack permission to test.

## Development

```bash
python -m unittest discover -s tests          # offline suite
MRPASS_NET_TESTS=1 python -m unittest discover -s tests   # includes live API checks
```

## Author

- **Mahmoud Ramadan Elbezzawy** — Computer Science & AI (Cybersecurity)
- GitHub: [mahmoudramadan06](https://github.com/mahmoudramadan06)
- LinkedIn: [mahmoud-r-elbezzawy](https://www.linkedin.com/in/mahmoud-r-elbezzawy)

## License

MIT — see [LICENSE](LICENSE).

Passphrase wordlist: [EFF short wordlist](https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt), CC-BY 3.0.
