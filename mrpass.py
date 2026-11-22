#!/usr/bin/env python3
"""
mrpass v4.0.0 - Advanced OSINT & Security Analysis CLI

A standalone, dependency-light security analysis tool for password strength
auditing, breach intelligence, phone/email OSINT, hash identification and
authorized password-audit wordlist generation.

Author: Mahmoud Ramadan Elbezzawy
License: MIT (see LICENSE)
Repository: https://github.com/mahmoudramadan06/mrpass

Privacy model
-------------
Local analysis (strength, patterns, hash ID, phone metadata, email syntax,
wordlists, generation) never leaves your machine. Online lookups only run
when you pass -sr/--search-leak, and then:
  * Passwords use the HIBP k-anonymity range API: only the first 5 hex chars
    of the SHA-1 hash are sent. The password itself is never transmitted.
  * Emails are sent to XposedOrNot (breach check) and debounce.io
    (disposable check); the domain part goes to public DNS-over-HTTPS
    resolvers for the MX lookup.
"""

import argparse
import csv
import getpass
import hashlib
import json
import math
import os
import re
import secrets
import string
import sys
import time
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None  # Online features report a clean error; offline features work.

VERSION = "4.0.0"
AUTHOR = "Mahmoud Ramadan Elbezzawy"
REPO_URL = "https://github.com/mahmoudramadan06/mrpass"

# --- ANSI Colors (disabled on non-TTY, --no-color, or NO_COLOR env) ---

COLORS_ENABLED = True

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"


def set_colors(enabled: bool) -> None:
    global COLORS_ENABLED, RESET, BOLD, DIM, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, GRAY
    COLORS_ENABLED = enabled
    if not enabled:
        RESET = BOLD = DIM = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = GRAY = ""


ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def vlen(s: str) -> int:
    """Visible length of a string that may contain ANSI escapes."""
    return len(ANSI_RE.sub("", s))


def print_box(title: str, lines: list, width: int = 75, color: str = CYAN, quiet: bool = False) -> None:
    if quiet:
        return
    title_str = f" {title} "
    top = f"{color}┌{title_str}{'─' * max(0, width - vlen(title_str) - 1)}┐{RESET}"
    print(top)
    for line in lines:
        if vlen(line) > width - 2:
            # Truncate over-long content lines rather than breaking the box.
            cut = width - 5
            plain = ANSI_RE.sub("", line)
            line = plain[:cut] + "..."
        pad = max(0, width - vlen(line) - 2)
        print(f"{color}│{RESET} {line}{' ' * pad}{color}│{RESET}")
    print(f"{color}└{'─' * width}┘{RESET}")


def banner() -> str:
    """Banner honoring the global color setting."""
    if COLORS_ENABLED:
        return BANNER
    return ANSI_RE.sub("", BANNER)


BANNER = "\033[90m" + r"""
    ____ ___  _________  ____  ____ _____
   / __ `__ \/ ___/ __ \/ __ \/ ___/ ___/
  / / / / / / /  / /_/ / /_/ (__  |__  )
 /_/ /_/ /_/_/  / .___/\__,_/____/____/
               /_/                       """ + "\033[0m\n"

# --- Data ---

# Top passwords seen in public breach corpuses (rockyou-style). Used for
# dictionary detection only.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567", "1234567890",
    "qwerty", "abc123", "111111", "123123", "admin", "letmein", "welcome", "monkey",
    "dragon", "football", "iloveyou", "sunshine", "master", "shadow", "ashley",
    "michael", "ninja", "mustang", "password1", "qwerty123", "baseball", "soccer",
    "hunter", "batman", "trustno1", "ranger", "thomas", "robert", "soccer10",
    "killer", "jordan", "jennifer", "zxcvbnm", "asdfgh", "passw0rd", "p@ssw0rd",
    "p@ssword", "1q2w3e4r", "1qaz2wsx", "qazwsx", "qwe123", "123qwe", "superman",
    "pokemon", "starwars", "charlie", "donald", "freedom", "whatever", "princess",
    "flower", "hottie", "loveme", "zaq1zaq1", "hello123", "test123", "root",
    "toor", "changeme", "default", "guest", "oracle", "cisco", "server",
    "computer", "michelle", "jessica", "pepper", "daniel", "babygirl", "654321",
    "112233", "121212", "222222", "555555", "666666", "7777777", "88888888",
    "999999", "000000", "00000000", "147258", "159753", "987654321", "741852963",
    "q1w2e3r4", "a1b2c3", "abcd1234", "1234abcd", "qwertyuiop", "asdfghjkl",
    "zxcvbn", "poiuyt", "lkjhgf", "mnbvcxz", "pass", "passwd", "pwd", "secret",
    "login", "user", "qwerty1", "qwerty12", "internet", "samsung", "pussy",
    "anthony", "justin", "andrea", "george", "cheese", "summer", "winter",
    "spring", "autumn", "january", "december", "liverpool", "arsenal", "chelsea",
}

KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321",
    "qwertzuiop",
    # Columns (vertical walks like '1qaz', '2wsx')
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik", "9ol", "0p",
]

LEET_TABLE = str.maketrans({
    "@": "a", "4": "a", "8": "b", "(": "c", "3": "e", "6": "g", "9": "g",
    "1": "i", "!": "i", "|": "i", "0": "o", "5": "s", "$": "s", "7": "t",
    "+": "t", "2": "z", "%": "x",
})

# Small local fallback list of well-known disposable providers; the live
# check via debounce.io (-sr) is the authoritative source.
DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "temp-mail.org", "10minutemail.com",
    "guerrillamail.com", "guerrillamail.net", "yopmail.com", "trashmail.com",
    "sharklasers.com", "getnada.com", "maildrop.cc", "dispostable.com",
    "fakeinbox.com", "throwawaymail.com", "moakt.com", "mintemail.com",
}

# EFF short wordlist (1296 words) for passphrase generation.
# Source: https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt (CC-BY 3.0)
EFF_WORDS = """acid acorn acre acts afar affix aged agent agile aging agony ahead aide aids aim ajar alarm alias alibi alien alike alive aloe aloft aloha alone amend amino ample amuse angel anger angle ankle apple april apron aqua area arena argue arise armed armor army aroma array arson art ashen ashes atlas atom attic audio avert avoid awake award awoke axis bacon badge bagel baggy baked baker balmy banjo barge barn bash basil bask batch bath baton bats blade blank blast blaze bleak blend bless blimp blink bloat blob blog blot blunt blurt blush boast boat body boil bok bolt boned boney bonus bony book booth boots boss botch both boxer breed bribe brick bride brim bring brink brisk broad broil broke brook broom brush buck bud buggy bulge bulk bully bunch bunny bunt bush bust busy buzz cable cache cadet cage cake calm cameo canal candy cane canon cape card cargo carol carry carve case cash cause cedar chain chair chant chaos charm chase cheek cheer chef chess chest chew chief chili chill chip chomp chop chow chuck chump chunk churn chute cider cinch city civic civil clad claim clamp clap clash clasp class claw clay clean clear cleat cleft clerk click cling clink clip cloak clock clone cloth cloud clump coach coast coat cod coil coke cola cold colt coma come comic comma cone cope copy coral cork cost cot couch cough cover cozy craft cramp crane crank crate crave crawl crazy creme crepe crept crib cried crisp crook crop cross crowd crown crumb crush crust cub cult cupid cure curl curry curse curve curvy cushy cut cycle dab dad daily dairy daisy dance dandy darn dart dash data date dawn deaf deal dean debit debt debug decaf decal decay deck decor decoy deed delay denim dense dent depth derby desk dial diary dice dig dill dime dimly diner dingy disco dish disk ditch ditzy dizzy dock dodge doing doll dome donor donut dose dot dove down dowry doze drab drama drank draw dress dried drift drill drive drone droop drove drown drum dry duck duct dude dug duke duo dusk dust duty dwarf dwell eagle early earth easel east eaten eats ebay ebony ebook echo edge eel eject elbow elder elf elk elm elope elude elves email emit empty emu enter entry envoy equal erase error erupt essay etch evade even evict evil evoke exact exit fable faced fact fade fall false fancy fang fax feast feed femur fence fend ferry fetal fetch fever fiber fifth fifty film filth final finch fit five flag flaky flame flap flask fled flick fling flint flip flirt float flock flop floss flyer foam foe fog foil folic folk food fool found fox foyer frail frame fray fresh fried frill frisk from front frost froth frown froze fruit gag gains gala game gap gas gave gear gecko geek gem genre gift gig gills given giver glad glass glide gloss glove glow glue goal going golf gong good gooey goofy gore gown grab grain grant grape graph grasp grass grave gravy gray green greet grew grid grief grill grip grit groom grope growl grub grunt guide gulf gulp gummy guru gush gut guy habit half halo halt happy harm hash hasty hatch hate haven hazel hazy heap heat heave hedge hefty help herbs hers hub hug hula hull human humid hump hung hunk hunt hurry hurt hush hut ice icing icon icy igloo image ion iron islam issue item ivory ivy jab jam jaws jazz jeep jelly jet jiffy job jog jolly jolt jot joy judge juice juicy july jumbo jump junky juror jury keep keg kept kick kilt king kite kitty kiwi knee knelt koala kung ladle lady lair lake lance land lapel large lash lasso last latch late lazy left legal lemon lend lens lent level lever lid life lift lilac lily limb limes line lint lion lip list lived liver lunar lunch lung lurch lure lurk lying lyric mace maker malt mama mango manor many map march mardi marry mash match mate math moan mocha moist mold mom moody mop morse most motor motto mount mouse mousy mouth move movie mower mud mug mulch mule mull mumbo mummy mural muse music musky mute nacho nag nail name nanny nap navy near neat neon nerd nest net next niece ninth nutty oak oasis oat ocean oil old olive omen onion only ooze opal open opera opt otter ouch ounce outer oval oven owl ozone pace pagan pager palm panda panic pants panty paper park party pasta patch path patio payer pecan penny pep perch perky perm pest petal petri petty photo plank plant plaza plead plot plow pluck plug plus poach pod poem poet pogo point poise poker polar polio polka polo pond pony poppy pork poser pouch pound pout power prank press print prior prism prize probe prong proof props prude prune pry pug pull pulp pulse puma punch punk pupil puppy purr purse push putt quack quake query quiet quill quilt quit quota quote rabid race rack radar radio raft rage raid rail rake rally ramp ranch range rank rant rash raven reach react ream rebel recap relax relay relic remix repay repel reply rerun reset rhyme rice rich ride rigid rigor rinse riot ripen rise risk ritzy rival river roast robe robin rock rogue roman romp rope rover royal ruby rug ruin rule runny rush rust rut sadly sage said saint salad salon salsa salt same sandy santa satin sauna saved savor sax say scale scam scan scare scarf scary scoff scold scoop scoot scope score scorn scout scowl scrap scrub scuba scuff sect sedan self send sepia serve set seven shack shade shady shaft shaky sham shape share sharp shed sheep sheet shelf shell shine shiny ship shirt shock shop shore shout shove shown showy shred shrug shun shush shut shy sift silk silly silo sip siren sixth size skate skew skid skier skies skip skirt skit sky slab slack slain slam slang slash slate slaw sled sleek sleep sleet slept slice slick slimy sling slip slit slob slot slug slum slurp slush small smash smell smile smirk smog snack snap snare snarl sneak sneer sniff snore snort snout snowy snub snuff speak speed spend spent spew spied spill spiny spoil spoke spoof spool spoon sport spot spout spray spree spur squad squat squid stack staff stage stain stall stamp stand stank stark start stash state stays steam steep stem step stew stick sting stir stock stole stomp stony stood stool stoop stop storm stout stove straw stray strut stuck stud stuff stump stung stunt suds sugar sulk surf sushi swab swan swarm sway swear sweat sweep swell swept swim swing swipe swirl swoop swore syrup tacky taco tag take tall talon tamer tank taper taps tarot tart task taste tasty taunt thank thaw theft theme thigh thing think thong thorn those throb thud thumb thump thus tiara tidal tidy tiger tile tilt tint tiny trace track trade train trait trap trash tray treat tree trek trend trial tribe trick trio trout truce truck trump trunk try tug tulip tummy turf tusk tutor tutu tux tweak tweet twice twine twins twirl twist uncle uncut undo unify union unit untie upon upper urban used user usher utter value vapor vegan venue verse vest veto vice video view viral virus visa visor vixen vocal voice void volt voter vowel wad wafer wager wages wagon wake walk wand wasp watch water wavy wheat whiff whole whoop wick widen widow width wife wifi wilt wimp wind wing wink wipe wired wiry wise wish wispy wok wolf womb wool woozy word work worry wound woven wrath wreck wrist xerox yahoo yam yard year yeast yelp yield yo-yo yodel yoga yoyo yummy zebra zero zesty zippy zone zoom""".split()

HEADERS = {"User-Agent": f"mrpass-cli/{VERSION} (+{REPO_URL})"}

EXPORT_DATA = []   # CSV rows (secrets masked)
RESULTS = []       # structured results for --json


# --- Helpers ---

def human_time(seconds: float) -> str:
    if seconds < 1:
        return "Instantly"
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 31_557_600:
        return f"{seconds / 86400:.1f} days"
    years = seconds / 31_557_600
    if years < 1_000_000:
        return f"{years:,.0f} years"
    return f"{years:.1e} years"


def human_time_log10(log10_seconds: float) -> str:
    """human_time in the log domain: safe for astronomically large values."""
    if log10_seconds < math.log10(31_557_600):
        return human_time(10 ** log10_seconds)
    years_log = log10_seconds - math.log10(31_557_600)
    if years_log < 6:
        return f"{10 ** years_log:,.0f} years"
    return f"1e{years_log:.0f} years"


def mask_secret(pw: str) -> str:
    """Display-safe form: keep first/last char only for length >= 4."""
    if len(pw) >= 4:
        return f"{pw[0]}{'*' * (len(pw) - 2)}{pw[-1]}"
    return "*" * len(pw)




def require_requests(feature: str):
    if requests is None:
        return f"'requests' is not installed; {feature} unavailable (pip install requests)"
    return None


# --- Password strength analysis ---

CHARSET_SIZE = {"lower": 26, "upper": 26, "digit": 10, "symbol": 32}


def _has_sequence(pw: str, min_run: int = 3) -> bool:
    """Detect ascending/descending character-code runs like 'abcd' or '4321'."""
    if len(pw) < min_run:
        return False
    run_dir, run_len = 0, 1
    for i in range(1, len(pw)):
        diff = ord(pw[i]) - ord(pw[i - 1])
        if diff == run_dir and diff in (1, -1):
            run_len += 1
            if run_len >= min_run:
                return True
        elif diff in (1, -1):
            run_dir, run_len = diff, 2
            if run_len >= min_run:
                return True
        else:
            run_dir, run_len = 0, 1
    return False


def _keyboard_positions() -> dict:
    """char -> [(row, col)] over rows and their reversals."""
    rows = KEYBOARD_ROWS + [r[::-1] for r in KEYBOARD_ROWS]
    pos = {}
    for r, row in enumerate(rows):
        for c, ch in enumerate(row):
            pos.setdefault(ch, []).append((r, c))
    return pos, rows


_KB_POS, _KB_ROWS = _keyboard_positions()


def _has_keyboard_walk(pw: str, min_run: int = 3) -> bool:
    """Linear scan: track active walks as (row, col, length) states.

    O(n * states-per-char); the v4.0.0 substring approach was superlinear and
    stalled bulk scans with long lines.
    """
    active = []
    for ch in pw.lower():
        new_active = []
        for (r, c, ln) in active:
            row = _KB_ROWS[r]
            if c + 1 < len(row) and row[c + 1] == ch:
                if ln + 1 >= min_run:
                    return True
                new_active.append((r, c + 1, ln + 1))
        for (r, c) in _KB_POS.get(ch, ()):
            new_active.append((r, c, 1))
        active = new_active
    return False


def detect_patterns(pw: str) -> list:
    """Human-readable weaknesses an attacker would exploit before brute force."""
    findings = []
    low = pw.lower()
    if re.search(r"(.)\1{2,}", low):
        findings.append("repeated characters (e.g. 'aaa')")
    if re.search(r"(.{2,4})\1{1,}", low):
        findings.append("repeated chunk (e.g. 'abcabc')")
    if _has_sequence(low):
        findings.append("sequential characters (e.g. 'abcd', '4321')")
    if _has_keyboard_walk(low):
        findings.append("keyboard walk (e.g. 'qwerty', 'asdf')")
    if re.search(r"(19|20)\d{2}", pw):
        findings.append("contains a year")
    # Strip trailing digits/punct first, then de-leet: 'P@ssw0rd99' -> 'password'.
    stripped = low.rstrip(string.digits + string.punctuation)
    normalized = low.translate(LEET_TABLE)
    normalized_stripped = stripped.translate(LEET_TABLE)
    if (low in COMMON_PASSWORDS or stripped in COMMON_PASSWORDS
            or normalized in COMMON_PASSWORDS or normalized_stripped in COMMON_PASSWORDS):
        findings.append("dictionary password (matches public breach lists)")
    return findings


def password_metrics(pw: str) -> dict:
    length = len(pw)
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_spec = any(not c.isalnum() for c in pw)

    space = (CHARSET_SIZE["lower"] * has_lower + CHARSET_SIZE["upper"] * has_upper
             + CHARSET_SIZE["digit"] * has_digit + CHARSET_SIZE["symbol"] * has_spec)
    entropy = length * math.log2(space) if space > 0 else 0.0

    # Average brute-force work factor is half the keyspace. Computed in the
    # log domain: space**length overflows floats for long passwords.
    if space > 0:
        log10_guesses = math.log10(0.5) + length * math.log10(space)
    else:
        log10_guesses = float("-inf")
    scenarios = {
        "online (rate-limited, 100/s)": 1e2,
        "offline slow hash (bcrypt, 100k/s)": 1e5,
        "offline fast hash (GPU, 100B/s)": 1e11,
    }
    crack_times = {
        name: human_time_log10(log10_guesses - math.log10(rate)) if space > 0 else "Instantly"
        for name, rate in scenarios.items()
    }

    findings = detect_patterns(pw)
    dictionary_hit = any("dictionary" in f for f in findings)

    # Score 0-4 from entropy, minus pattern penalties.
    if entropy < 28:
        score = 0
    elif entropy < 36:
        score = 1
    elif entropy < 50:
        score = 2
    elif entropy < 70:
        score = 3
    else:
        score = 4
    if dictionary_hit:
        score = 0
    else:
        score = max(0, score - min(len(findings), 2))

    labels = ["VERY WEAK", "WEAK", "MEDIUM", "STRONG", "EXCELLENT"]
    colors = [RED, RED, YELLOW, GREEN, CYAN]
    return {
        "length": length,
        "charset_space": space,
        "entropy": entropy,
        "classes": sum([has_lower, has_upper, has_digit, has_spec]),
        "findings": findings,
        "dictionary_hit": dictionary_hit,
        "crack_times": crack_times,
        "score": score,
        "label": labels[score],
        "color": colors[score],
    }


# --- Password & passphrase generation ---

def generate_password(length: int = 16, use_symbols: bool = True, avoid_ambiguous: bool = False) -> str:
    """CSPRNG password with guaranteed character classes.

    Raises ValueError for lengths too short to satisfy the required classes
    (the v3 loop hung forever here).
    """
    alphabet = string.ascii_letters + string.digits
    required = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if use_symbols:
        symbols = "!@#$%^&*()-_=+[]{};:,.<>?/"
        alphabet += symbols
        required.append(symbols)
    if avoid_ambiguous:
        ambiguous = "Il1O0"
        alphabet = "".join(c for c in alphabet if c not in ambiguous)
        required = ["".join(c for c in cls if c not in ambiguous) for cls in required]

    min_len = len(required)
    if length < min_len:
        raise ValueError(
            f"length {length} is too short to guarantee {min_len} character classes; "
            f"use at least {min_len}"
        )
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in cls for c in pw) for cls in required):
            return pw


def generate_passphrase(num_words: int = 5, separator: str = "-", capitalize: bool = False) -> str:
    if num_words < 1:
        raise ValueError("passphrase needs at least 1 word")
    if not EFF_WORDS:
        raise RuntimeError("embedded wordlist is empty")
    words = [secrets.choice(EFF_WORDS) for _ in range(num_words)]
    if capitalize:
        words = [w.capitalize() for w in words]
    return separator.join(words)


# --- Online intelligence (opt-in via -sr) ---

def check_password_hibp(password: str, max_retries: int = 2) -> tuple:
    """HaveIBeenPwned k-anonymity range check. Returns (count, error).

    Only the first 5 hex chars of the SHA-1 leave the machine.
    Retries politely on HTTP 429 rate limiting.
    """
    err = require_requests("breach check")
    if err:
        return None, err
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp = None
    for attempt in range(max_retries + 1):
        try:
            resp = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={**HEADERS, "Add-Padding": "true"}, timeout=10,
            )
        except requests.RequestException as e:
            return None, f"network error ({e.__class__.__name__})"
        if resp.status_code != 429:
            break
        if attempt < max_retries:
            time.sleep(2 * (attempt + 1))
    if resp.status_code == 404:
        return 0, None
    if resp.status_code == 429:
        return None, "HIBP rate limit hit (HTTP 429); wait a minute and retry"
    if resp.status_code != 200:
        return None, f"HIBP returned HTTP {resp.status_code}"
    for line in resp.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0].strip() == suffix:
            try:
                return int(parts[1]), None
            except ValueError:
                break
    return 0, None


def check_email_xon(email: str) -> tuple:
    """XposedOrNot breach check. Returns (list_of_breach_names, error)."""
    err = require_requests("breach check")
    if err:
        return None, err
    try:
        resp = requests.get(
            f"https://api.xposedornot.com/v1/check-email/{email}",
            headers=HEADERS, timeout=10,
        )
    except requests.RequestException as e:
        return None, f"network error ({e.__class__.__name__})"
    if resp.status_code == 404:
        return [], None  # not found in breaches
    if resp.status_code != 200:
        return None, f"XposedOrNot returned HTTP {resp.status_code}"
    try:
        breaches = resp.json().get("breaches") or []
    except ValueError:
        return None, "XposedOrNot returned invalid JSON"
    # API nests the list: {"breaches": [["LinkedIn", ...]]}
    while breaches and isinstance(breaches[0], list):
        breaches = breaches[0]
    return [str(b) for b in breaches], None


def check_email_disposable(email: str) -> tuple:
    """Disposable-domain check. Returns (is_disposable, error).

    Local well-known list first; debounce.io API refines it when online.
    """
    domain = email.rsplit("@", 1)[-1].lower()
    if domain in DISPOSABLE_DOMAINS:
        return True, None
    err = require_requests("disposable check")
    if err:
        return None, err
    try:
        resp = requests.get(
            "https://disposable.debounce.io/",
            params={"email": email}, headers=HEADERS, timeout=6,
        )
    except requests.RequestException as e:
        return None, f"network error ({e.__class__.__name__})"
    if resp.status_code != 200:
        return None, f"debounce.io returned HTTP {resp.status_code}"
    try:
        return resp.json().get("disposable") == "true", None
    except ValueError:
        return None, "debounce.io returned invalid JSON"


def check_mx(domain: str) -> tuple:
    """MX record lookup via public DNS-over-HTTPS. Returns (has_mx, error)."""
    err = require_requests("MX lookup")
    if err:
        return None, err
    endpoints = [
        ("https://cloudflare-dns.com/dns-query", {"accept": "application/dns-json"}),
        ("https://dns.google/resolve", {}),
    ]
    for url, extra_headers in endpoints:
        try:
            resp = requests.get(
                url, params={"name": domain, "type": "MX"},
                headers={**HEADERS, **extra_headers}, timeout=6,
            )
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        try:
            answers = resp.json().get("Answer") or []
        except ValueError:
            continue
        # RFC 7505: a null MX (exchange '.') means the domain accepts no mail.
        mx_hosts = [a.get("data", "") for a in answers if a.get("type") == 15]
        return any(h.strip().rstrip(".").split()[-1] not in ("", ".") for h in mx_hosts), None
    return None, "both DNS-over-HTTPS resolvers failed"


# --- Analysis modes ---

def analyze_password(password: str, check_online: bool, quiet: bool, silent: bool = False) -> None:
    metrics = password_metrics(password)
    masked = mask_secret(password)

    leak_count, leak_err = (None, None)
    if check_online:
        if not quiet and not silent:
            print(f"{MAGENTA}[»]{RESET} {DIM}Checking HaveIBeenPwned (k-anonymity, password never sent)...{RESET}")
        leak_count, leak_err = check_password_hibp(password)

    color = metrics["color"]
    if leak_count and leak_count > 0:
        color = RED

    # NOTE: no password-derived hash is stored or shown. An unsalted digest of
    # an analyzed password is offline verification material; the masked form is
    # enough for a human reviewing their own audit.
    EXPORT_DATA.append({
        "Target": masked,
        "Type": "Password",
        "Status": metrics["label"],
        "Leaks": leak_count if leak_count is not None else "Not checked",
        "Details": f"len={metrics['length']} entropy={metrics['entropy']:.1f}b",
    })
    RESULTS.append({
        "type": "password", "target_masked": masked,
        "label": metrics["label"], "score": metrics["score"],
        "length": metrics["length"], "entropy_bits": round(metrics["entropy"], 1),
        "findings": metrics["findings"], "crack_times": metrics["crack_times"],
        "pwned_count": leak_count, "pwned_error": leak_err,
    })

    if quiet or silent:
        if not silent:
            leak_txt = f"{leak_count:,}" if leak_count is not None else "N/A"
            print(f"{masked} : {color}{metrics['label']}{RESET} | Leaks: {leak_txt}")
        return

    lines = [
        f"{WHITE}• Target     :{RESET} {masked}  {DIM}(masked; no hash stored){RESET}",
        f"{WHITE}• Strength   :{RESET} {color}{BOLD}{metrics['label']}{RESET}  {DIM}(score {metrics['score']}/4){RESET}",
        f"{WHITE}• Length     :{RESET} {metrics['length']} chars  |  {WHITE}Entropy:{RESET} {metrics['entropy']:.1f} bits  |  {WHITE}Classes:{RESET} {metrics['classes']}/4",
    ]
    if check_online:
        if leak_count is not None:
            leak_line = (f"{RED}⚠ PWNED - seen {leak_count:,} times in breaches{RESET}"
                         if leak_count > 0 else f"{GREEN}✓ Not found in HIBP{RESET}")
        else:
            leak_line = f"{YELLOW}? Check failed: {leak_err}{RESET}"
        lines.append(f"{WHITE}• Breach     :{RESET} {leak_line}")
    for name, t in metrics["crack_times"].items():
        lines.append(f"{WHITE}• Crack {name}:{RESET} {YELLOW}{t}{RESET}")
    if metrics["findings"]:
        lines.append(f"{WHITE}• Weaknesses :{RESET} {RED}{metrics['findings'][0]}{RESET}")
        for f in metrics["findings"][1:]:
            lines.append(f"{WHITE}             {RESET} {RED}{f}{RESET}")
    print_box("PASSWORD ANALYSIS", lines, width=85, color=color)


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def analyze_email(email: str, check_online: bool, quiet: bool, silent: bool = False) -> None:
    email = email.strip()
    valid_syntax = bool(EMAIL_RE.match(email))
    domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""

    breaches = disposable = has_mx = None
    err_msgs = []

    if check_online:
        if not quiet and not silent:
            print(f"{MAGENTA}[»]{RESET} {DIM}Querying breach/disposable/DNS sources for {email}...{RESET}")
        if valid_syntax:
            breaches, err = check_email_xon(email)
            if err:
                err_msgs.append(f"breach check: {err}")
            disposable, err = check_email_disposable(email)
            if err:
                err_msgs.append(f"disposable check: {err}")
            has_mx, err = check_mx(domain)
            if err:
                err_msgs.append(f"MX lookup: {err}")
        else:
            err_msgs.append("invalid syntax; online checks skipped")

    if breaches:
        status, color = f"COMPROMISED ({len(breaches)} breaches)", RED
    elif breaches is not None:
        status, color = "CLEAN (no known breaches)", GREEN
    else:
        status, color = ("INVALID SYNTAX", RED) if not valid_syntax else ("NOT CHECKED (add -sr)", YELLOW)

    EXPORT_DATA.append({
        "Target": email, "Type": "Email", "Status": status.split(" (")[0],
        "Leaks": len(breaches) if breaches is not None else "Not checked",
        "Details": f"syntax={'ok' if valid_syntax else 'bad'} disposable={disposable} mx={has_mx}",
    })
    RESULTS.append({
        "type": "email", "target": email, "syntax_valid": valid_syntax, "domain": domain,
        "breaches": breaches, "disposable": disposable, "has_mx": has_mx,
        "errors": err_msgs, "status": status,
    })

    if quiet or silent:
        if not silent:
            print(f"{email} : {color}{status}{RESET} | Disposable: {disposable} | MX: {has_mx}")
        return

    lines = [
        f"{WHITE}• Email      :{RESET} {email}",
        f"{WHITE}• Syntax     :{RESET} {GREEN + 'VALID' + RESET if valid_syntax else RED + 'INVALID' + RESET}",
        f"{WHITE}• Status     :{RESET} {color}{BOLD}{status}{RESET}",
    ]
    if check_online and valid_syntax:
        lines.append(f"{WHITE}• MX records :{RESET} {(GREEN + 'YES' + RESET) if has_mx else (RED + 'NO' + RESET) if has_mx is False else YELLOW + 'unknown' + RESET}")
        lines.append(f"{WHITE}• Disposable :{RESET} {(RED + 'YES (burner)' + RESET) if disposable else (GREEN + 'NO' + RESET) if disposable is False else YELLOW + 'unknown' + RESET}")
        if breaches:
            shown = ", ".join(breaches[:6])
            more = f" (+{len(breaches) - 6} more)" if len(breaches) > 6 else ""
            lines.append(f"{WHITE}• Breaches   :{RESET} {RED}{shown}{more}{RESET}")
    for e in err_msgs:
        lines.append(f"{WHITE}• Warning    :{RESET} {YELLOW}{e}{RESET}")
    print_box("EMAIL OSINT REPORT", lines, width=85, color=color)


def analyze_phone(phone: str, quiet: bool, silent: bool = False) -> None:
    raw = phone.strip()
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone
        from phonenumbers.phonenumberutil import PhoneNumberType
    except ImportError:
        print(f"{RED}[✗] 'phonenumbers' is not installed; phone analysis unavailable (pip install phonenumbers).{RESET}")
        return

    candidates = [raw]
    if not raw.startswith("+"):
        candidates.insert(0, "+" + raw.lstrip("0"))

    parsed = None
    for cand in candidates:
        try:
            parsed = phonenumbers.parse(cand, None)
            break
        except phonenumbers.NumberParseException:
            continue

    type_names = {
        PhoneNumberType.MOBILE: "Mobile", PhoneNumberType.FIXED_LINE: "Fixed line",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed line or mobile",
        PhoneNumberType.TOLL_FREE: "Toll-free", PhoneNumberType.PREMIUM_RATE: "Premium rate",
        PhoneNumberType.SHARED_COST: "Shared cost", PhoneNumberType.VOIP: "VoIP",
        PhoneNumberType.PERSONAL_NUMBER: "Personal", PhoneNumberType.PAGER: "Pager",
        PhoneNumberType.UAN: "UAN", PhoneNumberType.VOICEMAIL: "Voicemail",
        PhoneNumberType.UNKNOWN: "Unknown",
    }

    if parsed is None:
        valid, color = "INVALID (unparseable)", RED
        EXPORT_DATA.append({"Target": raw, "Type": "Phone", "Status": "INVALID",
                            "Leaks": "N/A", "Details": "could not parse"})
        RESULTS.append({"type": "phone", "target": raw, "valid": False, "error": "unparseable"})
        if quiet or silent:
            if not silent:
                print(f"{raw} | Valid: {valid}")
        else:
            print_box("PHONE OSINT ANALYSIS", [
                f"{WHITE}• Target     :{RESET} {raw}",
                f"{WHITE}• Valid      :{RESET} {color}{BOLD}{valid}{RESET}",
            ], width=85, color=color)
        return

    is_valid = phonenumbers.is_valid_number(parsed)
    is_possible = phonenumbers.is_possible_number(parsed)
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    country = geocoder.description_for_number(parsed, "en") or "Unknown"
    network = carrier.name_for_number(parsed, "en") or "Unknown"
    tzones = ", ".join(timezone.time_zones_for_number(parsed)) or "Unknown"
    ntype = type_names.get(phonenumbers.number_type(parsed), "Unknown")
    region = phonenumbers.region_code_for_number(parsed) or "??"

    valid_txt = "YES" if is_valid else ("POSSIBLE (not confirmed)" if is_possible else "NO")
    color = GREEN if is_valid else (YELLOW if is_possible else RED)
    clean = e164.replace("+", "")
    dork_1 = f'intext:"{e164}" OR intext:"{clean}"'
    dork_2 = f'ext:txt OR ext:csv OR ext:xlsx "{e164}"'

    EXPORT_DATA.append({
        "Target": e164, "Type": "Phone", "Status": valid_txt, "Leaks": "N/A",
        "Details": f"Country: {country} | Carrier: {network} | Type: {ntype}",
    })
    RESULTS.append({
        "type": "phone", "target": e164, "valid": is_valid, "possible": is_possible,
        "region": region, "country": country, "carrier": network, "line_type": ntype,
        "timezones": tzones, "e164": e164, "international": intl, "national": national,
        "osint_dorks": [dork_1, dork_2],
    })

    if quiet or silent:
        if not silent:
            print(f"{e164} | Valid: {valid_txt} | Country: {country} | Carrier: {network} | Type: {ntype}")
        return

    lines = [
        f"{WHITE}• Target     :{RESET} {e164}",
        f"{WHITE}• Valid      :{RESET} {color}{BOLD}{valid_txt}{RESET}",
    ]
    if is_valid or is_possible:
        lines.extend([
            f"{WHITE}• Country    :{RESET} {country} ({region})",
            f"{WHITE}• Carrier    :{RESET} {YELLOW}{network}{RESET}",
            f"{WHITE}• Line type  :{RESET} {ntype}",
            f"{WHITE}• Timezone   :{RESET} {tzones}",
            f"{WHITE}• Formats    :{RESET} intl: {intl} | nat: {national}",
            f"{WHITE}• OSINT dork :{RESET} {CYAN}{dork_1}{RESET}",
            f"{WHITE}• Leak dork  :{RESET} {CYAN}{dork_2}{RESET}",
            f"{DIM}  (paste dorks into a search engine yourself; nothing is sent){RESET}",
        ])
    print_box("PHONE OSINT ANALYSIS", lines, width=85, color=color)


# --- Hash identification ---

HASH_PATTERNS = [
    # (name, regex, hashcat mode or None, john format or None, note)
    ("JWT (JSON Web Token)", re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$"), 16500, "jwt", "not a password hash"),
    ("Argon2", re.compile(r"^\$argon2(id?|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]*$"), None, "argon2", "modern KDF; hashcat unsupported"),
    ("bcrypt", re.compile(r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$"), 3200, "bcrypt", "Blowfish-based, adaptive"),
    ("scrypt", re.compile(r"^\$scrypt\$"), 8900, "scrypt", "memory-hard KDF"),
    ("PBKDF2", re.compile(r"^\$pbkdf2(-sha256|-sha512)?\$"), None, "pbkdf2", "KDF wrapper format"),
    ("Django PBKDF2-SHA256", re.compile(r"^pbkdf2_sha256\$\d+\$[^$]+\$[A-Za-z0-9+/=]+$"), 10000, "django", None),
    ("md5crypt", re.compile(r"^\$1\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{22}$"), 500, "md5crypt", None),
    ("Apache MD5 (apr1)", re.compile(r"^\$apr1\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{22}$"), 1600, "md5crypt-long", None),
    ("sha256crypt", re.compile(r"^\$5\$(rounds=\d+\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}$"), 7400, "sha256crypt", None),
    ("sha512crypt", re.compile(r"^\$6\$(rounds=\d+\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$"), 1800, "sha512crypt", None),
    ("phpass (WordPress/phpBB)", re.compile(r"^\$[PH]\$[./0-9A-Za-z]{31}$"), 400, "phpass", None),
    ("Drupal 7 (SHA-512)", re.compile(r"^\$S\$[./0-9A-Za-z]{52}$"), 7900, "drupal7", None),
    ("LDAP SSHA (salted SHA-1)", re.compile(r"^\{SSHA\}[A-Za-z0-9+/=]+$"), 101, "ssha", "base64"),
    ("LDAP SHA", re.compile(r"^\{SHA\}[A-Za-z0-9+/=]+$"), 101, None, "base64"),
    ("LDAP MD5", re.compile(r"^\{MD5\}[A-Za-z0-9+/=]+$"), 6300, None, "base64"),
    ("Kerberos 5", re.compile(r"^\$krb5[0-9a-z]*\$"), None, "krb5", None),
    ("MySQL 4.1+ (SHA-1)", re.compile(r"^\*[A-Fa-f0-9]{40}$"), 300, "mysql-sha1", None),
    ("MSSQL (2005/2012)", re.compile(r"^0x0100[A-Fa-f0-9]{8}[A-Fa-f0-9]{40,128}$"), 132, "mssql", None),
    ("CRC-32", re.compile(r"^[a-fA-F0-9]{8}$"), 11500, "crc32", "checksum, not a password hash"),
    ("MySQL pre-4.1", re.compile(r"^[a-fA-F0-9]{16}$"), 200, "mysql", "weak, legacy"),
    ("MD5 / NTLM / LM", re.compile(r"^[a-fA-F0-9]{32}$"), 0, "raw-md5", "also: NTLM (hashcat 1000), LM (3000)"),
    ("SHA-1 / RIPEMD-160", re.compile(r"^[a-fA-F0-9]{40}$"), 100, "raw-sha1", "also: RIPEMD-160 (6000)"),
    ("SHA-224", re.compile(r"^[a-fA-F0-9]{56}$"), 1300, "raw-sha224", None),
    ("SHA-256 / SHA3-256 / BLAKE2s", re.compile(r"^[a-fA-F0-9]{64}$"), 1400, "raw-sha256", "also: SHA3-256 (17400), BLAKE2s"),
    ("SHA-384 / SHA3-384", re.compile(r"^[a-fA-F0-9]{96}$"), 10800, "raw-sha384", "also: SHA3-384 (17500)"),
    ("SHA-512 / SHA3-512 / BLAKE2b", re.compile(r"^[a-fA-F0-9]{128}$"), 1700, "raw-sha512", "also: SHA3-512 (17600), BLAKE2b"),
]


def identify_hash(hash_str: str) -> None:
    h = hash_str.strip()
    matches = [(name, hc, john, note) for name, rx, hc, john, note in HASH_PATTERNS if rx.match(h)]

    RESULTS.append({
        "type": "hash_identify", "target_masked": mask_secret(h) if len(h) >= 8 else h,
        "length": len(h),
        "matches": [{"name": m[0], "hashcat": m[1], "john": m[2], "note": m[3]} for m in matches],
    })

    lines = [
        f"{WHITE}• Hash       :{RESET} {h[:60]}{'...' if len(h) > 60 else ''}",
        f"{WHITE}• Length     :{RESET} {len(h)} chars",
    ]
    if not matches:
        lines.append(f"{WHITE}• Matches    :{RESET} {RED}Unknown or unsupported format{RESET}")
    else:
        for i, (name, hc, john, note) in enumerate(matches):
            prefix = "• Matches    :" if i == 0 else "             "
            extra = f"  {DIM}(hashcat -m {hc}" + (f", john --format={john}" if john else "") + f"){RESET}" if hc else (f"  {DIM}(john --format={john}){RESET}" if john else "")
            lines.append(f"{WHITE}{prefix}{RESET} {YELLOW}{name}{RESET}{extra}")
            if note:
                lines.append(f"{WHITE}             {RESET} {DIM}{note}{RESET}")
    print_box("HASH IDENTIFIER", lines, width=85, color=MAGENTA)


# --- Wordlist mutator (authorized password-audit use) ---

MUTATE_LEET = str.maketrans({
    "a": "@", "A": "@", "e": "3", "E": "3", "i": "1", "I": "1",
    "o": "0", "O": "0", "s": "$", "S": "$", "t": "7", "T": "7",
    "b": "8", "B": "8", "g": "9", "G": "9",
})


def _suffixes(level: int, years: list) -> list:
    year_strs = [str(y) for y in years]
    base = ["", "!", "1", "12", "123"] + year_strs
    if level >= 2:
        base += ["!!", "@", "#", "1234", "12345", "01", "007", "111", "000",
                 "69", "99", "321", "!@#", "?"] + [f"{y}!" for y in years]
    if level >= 3:
        base += ["123456", "1234567", "12345678", "654321", "112233"] + [str(n) for n in range(100)]
    # Dedupe while preserving order.
    seen, out = set(), []
    for s in base:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def mutate_words(words: list, years: list = None, level: int = 2,
                 use_leet: bool = True, min_len: int = 1, max_len: int = 64) -> list:
    """Deterministic audit wordlist from base words. Bounded size, deduped."""
    if years is None:
        years = [datetime.now().year]
    suffixes = _suffixes(level, years)
    seen, results = set(), []
    for word in words:
        word = word.strip()
        if not word:
            continue
        variants = {word.lower(), word.capitalize(), word.upper()}
        if use_leet:
            variants |= {v.translate(MUTATE_LEET) for v in list(variants)}
        for v in sorted(variants):
            for suf in suffixes:
                cand = v + suf
                if min_len <= len(cand) <= max_len and cand not in seen:
                    seen.add(cand)
                    results.append(cand)
    return results


def run_mutator(target: str, out_file, args) -> None:
    words = [w for w in re.split(r"[,\s]+", target) if w]
    if not words:
        print(f"{RED}[✗] Mutator needs at least one base word: mrpass \"word1,word2\" -m [out.txt]{RESET}")
        sys.exit(1)
    years = args.years if args.years else [datetime.now().year]
    mutations = mutate_words(words, years=years, level=args.level,
                             use_leet=not args.no_leet, min_len=args.min, max_len=args.max)
    RESULTS.append({
        "type": "mutator", "base_words": words, "count": len(mutations),
        "level": args.level, "years": years, "leet": not args.no_leet,
        "output": out_file or "console",
    })
    if out_file:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write("\n".join(mutations) + "\n")
        print(f"{GREEN}[✓] {len(mutations):,} mutations from {len(words)} base word(s) saved to {BOLD}{out_file}{RESET}")
        print(f"{DIM}    level={args.level} years={years} leet={'on' if not args.no_leet else 'off'}{RESET}")
    else:
        print_box(f"WORDLIST MUTATOR ({len(mutations):,} candidates)", [
            f"{WHITE}• Base words :{RESET} {', '.join(words[:8])}",
            f"{WHITE}• Settings   :{RESET} level {args.level} | years {years} | leet {'on' if not args.no_leet else 'off'}",
            f"{WHITE}• Samples    :{RESET} {', '.join(mutations[:8])} ...",
            f"{DIM}  Save with: mrpass \"{target}\" -m wordlist.txt{RESET}",
            f"{DIM}  For authorized security audits only.{RESET}",
        ], width=85, color=CYAN)


# --- Export ---

CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def _csv_safe(value) -> str:
    """Neutralize spreadsheet formula injection in exported cells.

    Masked targets keep their first character, so a password like '-abc!' or
    an email crafted to start with '=' would otherwise execute as a formula
    when the report is opened in a spreadsheet app.
    """
    s = str(value)
    if s and s[0] in CSV_FORMULA_PREFIXES:
        return "'" + s
    return s


def export_csv(filename: str, msg_file=None) -> bool:
    """Write the CSV report. Returns True on success or when there is simply
    nothing to export (a warning, not a failure); False on write errors."""
    out = msg_file or sys.stdout
    if not EXPORT_DATA:
        print(f"{YELLOW}[!] Nothing to export (no analysis results this run).{RESET}", file=out)
        return True
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Target", "Type", "Status", "Leaks", "Details"])
            writer.writeheader()
            for row in EXPORT_DATA:
                writer.writerow({k: _csv_safe(v) for k, v in row.items()})
        print(f"{GREEN}[✓] Report exported to {BOLD}{filename}{RESET} ({len(EXPORT_DATA)} rows; secrets masked)",
              file=out)
        return True
    except OSError as e:
        print(f"{RED}[✗] Error saving CSV: {e}{RESET}", file=out)
        return False


# --- CLI ---

class CustomHelpFormatter(argparse.HelpFormatter):
    def format_help(self):
        return (
            f"{banner()}\n"
            f"{DIM}mrpass v{VERSION}: Advanced OSINT & Security Analysis Tool{RESET}\n\n"
            f"{BOLD}SYNTAX:{RESET}\n"
            f"  mrpass [TARGET] [OPTIONS]\n\n"
            f"{BOLD}TARGET MODES:{RESET}\n"
            f"  {GREEN}-ps, --password{RESET}       Password strength, patterns, crack-time scenarios\n"
            f"  {GREEN}-em, --email{RESET}          Email syntax, breaches, disposable and MX checks\n"
            f"  {GREEN}-ph, --phone{RESET}          Phone validation, carrier, country, line type, dorks\n"
            f"  {GREEN}-id, --identify{RESET}       Identify hash types (25+ formats, hashcat/john hints)\n"
            f"  {GREEN}-m,  --mutate [FILE]{RESET}  Audit wordlist from base words (authorized use only)\n"
            f"  {GREEN}-n,  --new [LENGTH]{RESET}   Generate a CSPRNG password (default: 16)\n"
            f"  {GREEN}-pp, --passphrase [N]{RESET} Generate a wordlist-based passphrase (default: 5 words)\n\n"
            f"{BOLD}OPTIONS:{RESET}\n"
            f"  {GREEN}-sr, --search-leak{RESET}    Opt-in online lookups (HIBP k-anonymity, XON, debounce, DNS)\n"
            f"  {GREEN}-f,  --file FILE{RESET}      Bulk mode: read targets from a text file\n"
            f"  {GREEN}-o,  --output FILE{RESET}    Export analysis results to CSV (masked;\n"
            f"  {GREEN}{RESET}                          -ps/-em/-ph results, not generation)\n"
            f"  {GREEN}-q,  --quiet{RESET}          Minimal one-line output per target\n"
            f"  {GREEN}--json{RESET}                Machine-readable JSON output\n"
            f"  {GREEN}--no-color{RESET}            Disable ANSI colors (also: NO_COLOR env)\n"
            f"  {GREEN}--no-symbols{RESET}          Generate alphanumeric-only passwords\n"
            f"  {GREEN}--separator SEP{RESET}       Passphrase word separator (default: '-')\n"
            f"  {GREEN}--years A-B{RESET}           Mutator year suffixes (default: current year)\n"
            f"  {GREEN}--level 1-3{RESET}           Mutator intensity (default: 2)\n"
            f"  {GREEN}--no-leet{RESET}             Disable leetspeak mutations\n"
            f"  {GREEN}--min N / --max N{RESET}     Mutator length bounds\n"
            f"  {GREEN}--version{RESET}             Print version and exit\n"
            f"  {GREEN}-h,  --help{RESET}           Show this help\n\n"
            f"{BOLD}EXAMPLES:{RESET}\n"
            f"  {YELLOW}1.{RESET} mrpass -ps -sr                  # hidden password prompt + breach check\n"
            f"  {YELLOW}2.{RESET} mrpass \"user@mail.com\" -em -sr   # breach, disposable, MX checks\n"
            f"  {YELLOW}3.{RESET} mrpass \"+2010xxxxxxxx\" -ph       # phone OSINT (fully local)\n"
            f"  {YELLOW}4.{RESET} mrpass \"5d41402abc...\" -id       # hash identification\n"
            f"  {YELLOW}5.{RESET} mrpass -pp 6                    # 6-word passphrase\n"
            f"  {YELLOW}6.{RESET} mrpass -f targets.txt -ps -sr -o report.csv --json\n"
        )


def parse_years(spec):
    """'2024' -> [2024]; '2018-2026' -> [2018..2026]; None -> None."""
    if spec is None:
        return None
    spec = spec.strip()
    m = re.match(r"^(\d{4})\s*-\s*(\d{4})$", spec)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if a > b:
            a, b = b, a
        if b - a > 60:
            raise ValueError("year range too wide (max 60 years)")
        return list(range(a, b + 1))
    if re.match(r"^\d{4}$", spec):
        return [int(spec)]
    raise ValueError(f"invalid --years value: {spec!r} (use YYYY or YYYY-YYYY)")


def read_password_target() -> str:
    """Password from stdin when piped, else a hidden prompt. Never echoes."""
    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        return line.rstrip("\r\n")
    return getpass.getpass("Password to analyze (hidden): ")


def main() -> int:
    parser = argparse.ArgumentParser(formatter_class=CustomHelpFormatter, add_help=False)
    parser.add_argument("target", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("-ps", "--password", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-em", "--email", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-ph", "--phone", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-sr", "--search-leak", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-id", "--identify", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-m", "--mutate", nargs="?", const="console", type=str, help=argparse.SUPPRESS)
    parser.add_argument("-n", "--new", nargs="?", const=16, type=int, help=argparse.SUPPRESS)
    parser.add_argument("-pp", "--passphrase", nargs="?", const=5, type=int, help=argparse.SUPPRESS)
    parser.add_argument("-f", "--file", type=str, help=argparse.SUPPRESS)
    parser.add_argument("-o", "--output", type=str, help=argparse.SUPPRESS)
    parser.add_argument("-q", "--quiet", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-color", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-symbols", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--separator", type=str, default="-", help=argparse.SUPPRESS)
    parser.add_argument("--years", type=str, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--level", type=int, choices=[1, 2, 3], default=2, help=argparse.SUPPRESS)
    parser.add_argument("--no-leet", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--min", type=int, default=1, help=argparse.SUPPRESS)
    parser.add_argument("--max", type=int, default=64, help=argparse.SUPPRESS)
    parser.add_argument("--version", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-h", "--help", action="help", help=argparse.SUPPRESS)

    # Colors decided before parsing so argparse error output respects them too.
    pre_no_color = (not sys.stdout.isatty() or bool(os.environ.get("NO_COLOR"))
                    or "--no-color" in sys.argv or "--json" in sys.argv)
    set_colors(not pre_no_color)

    if len(sys.argv) == 1:
        print(banner())
        parser.print_help()
        return 1

    args = parser.parse_args()  # argparse exits 2 on bad usage (no longer swallowed)

    if args.version:
        print(f"mrpass {VERSION}")
        return 0

    try:
        args.years = parse_years(args.years)
    except ValueError as e:
        print(f"{RED}[✗] {e}{RESET}", file=sys.stderr)
        return 2

    if args.target == "info":
        if not args.quiet and not args.json:
            print(banner())
        print_box("DEVELOPER INFO & TOOL SPECS", [
            f"{WHITE}▸ Author      :{RESET} {AUTHOR}",
            f"{WHITE}▸ Academic    :{RESET} Computer Science & AI (Cybersecurity Focus)",
            f"{WHITE}▸ GitHub      :{RESET} github.com/mahmoudramadan06",
            f"{WHITE}▸ LinkedIn    :{RESET} linkedin.com/in/mahmoud-r-elbezzawy",
            f"{WHITE}▸ Repository  :{RESET} {REPO_URL}",
            f"{WHITE}▸ Version     :{RESET} {VERSION}",
            f"{WHITE}▸ Modules     :{RESET} password strength & pattern analysis",
            f"{WHITE}                {RESET} breach intel (HIBP k-anonymity, XON)",
            f"{WHITE}                {RESET} email syntax/disposable/MX checks",
            f"{WHITE}                {RESET} phone validation, carrier & geocoding",
            f"{WHITE}                {RESET} 25-format hash identifier",
            f"{WHITE}                {RESET} CSPRNG password & passphrase generator",
            f"{WHITE}                {RESET} authorized-audit wordlist mutator",
        ], width=85, color=BLUE, quiet=args.quiet or args.json)
        return 0

    if args.new is not None:
        try:
            pwd = generate_password(args.new, use_symbols=not args.no_symbols)
        except ValueError as e:
            print(f"{RED}[✗] {e}{RESET}", file=sys.stderr)
            return 2
        metrics = password_metrics(pwd)
        RESULTS.append({
            "type": "generate", "length": args.new, "password": pwd,
            "entropy_bits": round(metrics["entropy"], 1),
        })
        if args.quiet or args.json:
            if not args.json:
                print(pwd)
        else:
            print_box("SECURE GENERATOR", [
                f"{WHITE}• Generated  :{RESET} {GREEN}{BOLD}{pwd}{RESET}",
                f"{WHITE}• Length     :{RESET} {args.new} characters ({metrics['entropy']:.1f} bits)",
                f"{WHITE}• Crack (fast GPU):{RESET} {YELLOW}{metrics['crack_times']['offline fast hash (GPU, 100B/s)']}{RESET}",
            ], width=85, color=GREEN)

    if args.passphrase is not None:
        try:
            phrase = generate_passphrase(args.passphrase, separator=args.separator)
        except (ValueError, RuntimeError) as e:
            print(f"{RED}[✗] {e}{RESET}", file=sys.stderr)
            return 2
        entropy = args.passphrase * math.log2(len(EFF_WORDS))
        RESULTS.append({
            "type": "passphrase", "words": args.passphrase, "passphrase": phrase,
            "entropy_bits": round(entropy, 1),
        })
        if args.quiet or args.json:
            if not args.json:
                print(phrase)
        else:
            print_box("PASSPHRASE GENERATOR", [
                f"{WHITE}• Generated  :{RESET} {GREEN}{BOLD}{phrase}{RESET}",
                f"{WHITE}• Words      :{RESET} {args.passphrase} from a {len(EFF_WORDS)}-word list ({entropy:.1f} bits)",
            ], width=85, color=GREEN)

    if args.identify and args.target:
        identify_hash(args.target)

    if args.mutate and args.target:
        out_file = None if args.mutate == "console" else args.mutate
        run_mutator(args.target, out_file, args)
    elif args.mutate and not args.target:
        print(f"{RED}[✗] Mutator needs a base word: mrpass \"keyword\" -m [out.txt]{RESET}", file=sys.stderr)
        return 1

    # Bulk / single-target analysis modes
    needs_target = args.password or args.email or args.phone
    if needs_target:
        targets = []
        if args.target:
            targets.append(args.target)
        if args.file:
            if os.path.isfile(args.file):
                with open(args.file, "r", encoding="utf-8-sig") as f:  # utf-8-sig strips BOM
                    targets.extend(line.strip() for line in f if line.strip())
            else:
                print(f"{RED}[✗] File '{args.file}' not found.{RESET}", file=sys.stderr)
                return 1
        if not targets:
            if args.password:
                # Hidden prompt / stdin pipe: never echo the password.
                t = read_password_target()
                if not t:
                    print(f"{RED}[✗] Empty password.{RESET}", file=sys.stderr)
                    return 1
                targets.append(t)
            else:
                print(f"{YELLOW}[!] No target provided. Run 'mrpass -h' for usage.{RESET}", file=sys.stderr)
                return 1

        for i, t in enumerate(targets):
            if i and args.search_leak:
                time.sleep(0.15)  # be polite to free APIs during bulk scans
            if args.password:
                analyze_password(t, args.search_leak, args.quiet, silent=args.json)
            elif args.email:
                analyze_email(t, args.search_leak, args.quiet, silent=args.json)
            elif args.phone:
                analyze_phone(t, args.quiet, silent=args.json)

    export_failed = False
    if args.output:
        # In JSON mode stdout must stay machine-readable: confirmations go to stderr.
        export_failed = not export_csv(args.output, msg_file=sys.stderr if args.json else None)

    if args.json:
        print(json.dumps({
            "mrpass_version": VERSION,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "results": RESULTS,
        }, indent=2))

    return 1 if export_failed else 0


if __name__ == "__main__":
    sys.exit(main())
