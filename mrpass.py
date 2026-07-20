#!/usr/bin/env python3
import sys
import subprocess
import importlib.util

# --- Auto-Installer for External Dependencies ---
REQUIRED_PACKAGES = {"requests": "requests", "phonenumbers": "phonenumbers"}

def check_and_install_dependencies():
    missing = []
    for pkg, pip_name in REQUIRED_PACKAGES.items():
        if importlib.util.find_spec(pkg) is None:
            missing.append(pip_name)
    
    if missing:
        print(f"\033[93m[!] Missing required dependencies: {', '.join(missing)}\033[0m")
        print(f"\033[94m[»] Automatically installing missing packages via pip...\033[0m")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing], 
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"\033[92m[✓] Dependencies installed successfully! Starting mrpass...\033[0m\n")
        except Exception as e:
            print(f"\033[91m[✗] Failed to auto-install packages. Please run manually: pip install {' '.join(missing)}\033[0m")
            sys.exit(1)

check_and_install_dependencies()

# --- Standard Imports ---
import string
import math
import hashlib
import secrets
import argparse
import requests
import os
import re
import csv
from datetime import datetime

# --- ANSI Colors ---
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
GRAY    = "\033[90m"

ANSI_RE = re.compile(r"\033\[[0-9;]*m")

def vlen(s: str) -> int:
    return len(ANSI_RE.sub("", s))

def print_box(title: str, lines: list, width: int = 75, color: str = CYAN, quiet: bool = False):
    if quiet: return
    title_str = f" {title} "
    top = f"{color}┌{title_str}{'─' * max(0, width - vlen(title_str) - 1)}┐{RESET}"
    print(top)
    for line in lines:
        pad = max(0, width - vlen(line) - 2)
        print(f"{color}│{RESET} {line}{' ' * pad}{color}│{RESET}")
    print(f"{color}└{'─' * width}┘{RESET}")

VERSION = "3.2.1 (Ultimate Pentest Edition)"
AUTHOR = "Mahmoud Ramadan Elbezzawy"

BANNER = f"\033[90m" + r"""
    ____ ___  _________  ____  ____ _____
   / __ `__ \/ ___/ __ \/ __ \/ ___/ ___/
  / / / / / / /  / /_/ / /_/ (__  |__  ) 
 /_/ /_/ /_/_/  / .___/\__,_/____/____/  
               /_/                       """ + f"\033[0m\n\033[90m:: v{VERSION} :: Engineered by {AUTHOR}\033[0m\n"

COMMON_PASSWORDS = {"123456", "password", "123456789", "qwerty", "12345", "12345678", "admin", "welcome"}
HEADERS = {"User-Agent": "mrpass-cli-osint-tool/3.2"}
EXPORT_DATA = []

# --- OSINT & API Functions ---

def check_password_hibp(password: str) -> int:
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=7)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if line.split(':')[0] == suffix:
                    return int(line.split(':')[1])
    except: pass
    return 0

def check_email_xon(email: str) -> list:
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            breaches = response.json().get("breaches", [])
            return breaches[0] if breaches and isinstance(breaches[0], list) else breaches
    except: pass
    return []

def check_email_disposable(email: str) -> bool:
    url = f"https://disposable.debounce.io/?email={email}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=5)
        if response.status_code == 200:
            return response.json().get("disposable") == "true"
    except: pass
    return False

# --- Core Logic Functions ---

def calculate_metrics(password: str) -> dict:
    length = len(password)
    has_lower, has_upper = any(c.islower() for c in password), any(c.isupper() for c in password)
    has_digit, has_spec = any(c.isdigit() for c in password), any(c in string.punctuation for c in password)
    
    space = (26 * has_lower) + (26 * has_upper) + (10 * has_digit) + (32 * has_spec)
    combinations = math.pow(space, length) if space > 0 else 0
    seconds_to_crack = combinations / (10**10) if combinations else 0
    
    if seconds_to_crack < 1: time_display = "Instantly"
    elif seconds_to_crack < 3600: time_display = f"{seconds_to_crack / 60:.2f} mins"
    elif seconds_to_crack < 31536000: time_display = f"{seconds_to_crack / 86400:.2f} days"
    else: time_display = f"{(seconds_to_crack / 31536000):,.0f} years"
        
    return {"length": length, "entropy": length * math.log2(space) if space > 0 else 0, "time": time_display, "cond": sum([has_lower, has_upper, has_digit, has_spec])}

def generate_strong_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in string.punctuation for c in password)):
            return password

def analyze_password(password: str, check_online: bool, quiet: bool):
    metrics = calculate_metrics(password)
    is_common = password.lower() in COMMON_PASSWORDS
    leak_count = -1

    if check_online and not is_common:
        if not quiet: print(f"{MAGENTA}[»]{RESET} {DIM}Checking OSINT databases for password...{RESET}")
        leak_count = check_password_hibp(password)
    elif is_common: leak_count = 999999

    if metrics["length"] >= 12 and metrics["cond"] == 4: msg, color = "STRONG", GREEN
    elif metrics["length"] >= 8 and metrics["cond"] >= 2: msg, color = "MEDIUM", YELLOW
    else: msg, color = "WEAK", RED

    EXPORT_DATA.append({
        "Target": password, "Type": "Password", "Status": msg, 
        "Leaks": leak_count if leak_count >= 0 else "Not Checked", "Details": f"ETA: {metrics['time']}"
    })

    if quiet:
        print(f"{password} : {color}{msg}{RESET} | Leaks: {leak_count if leak_count >=0 else 'N/A'}")
        return

    lines = [
        f"{WHITE}• Target     :{RESET} {password}",
        f"{WHITE}• Strength   :{RESET} {color}{BOLD}{msg}{RESET}",
        f"{WHITE}• Length     :{RESET} {metrics['length']} chars  |  {WHITE}Entropy:{RESET} {metrics['entropy']:.1f} bits",
        f"{WHITE}• ETA Crack  :{RESET} {YELLOW}{BOLD}{metrics['time']}{RESET}"
    ]
    if check_online or is_common:
        lines.insert(2, f"{WHITE}• OSINT      :{RESET} {RED}⚠️ LEAKED ({leak_count:,}){RESET}" if leak_count > 0 else f"{WHITE}• OSINT      :{RESET} {GREEN}✓ CLEAN{RESET}")
    print_box("PASSWORD ANALYSIS", lines, color=RED if leak_count > 0 else color)

def analyze_email(email: str, check_online: bool, quiet: bool):
    if not check_online:
        print(f"{YELLOW}[!] Email analysis requires (-sr) flag.{RESET}")
        return

    if not quiet: print(f"{MAGENTA}[»]{RESET} {DIM}Querying threat intelligence for {email}...{RESET}")
    breaches = check_email_xon(email)
    is_disp = check_email_disposable(email)

    status_msg = f"COMPROMISED ({len(breaches)})" if breaches else "CLEAN"
    color = RED if breaches else GREEN
    disp_msg = f"{RED}YES (Burner/Temp){RESET}" if is_disp else f"{GREEN}NO (Valid){RESET}"

    EXPORT_DATA.append({
        "Target": email, "Type": "Email", "Status": status_msg.split(' ')[0],
        "Leaks": len(breaches), "Details": f"Disposable: {'Yes' if is_disp else 'No'}"
    })

    if quiet:
        print(f"{email} : {color}{status_msg}{RESET} | Disp: {is_disp}")
        return

    lines = [
        f"{WHITE}• Email      :{RESET} {email}",
        f"{WHITE}• OSINT      :{RESET} {color}{BOLD}{status_msg}{RESET}",
        f"{WHITE}• Disposable :{RESET} {disp_msg}"
    ]
    if breaches: lines.append(f"{WHITE}• Sources    :{RESET} {', '.join(breaches[:4])}...")
    print_box("EMAIL OSINT REPORT", lines, color=color)

def analyze_phone(phone: str, quiet: bool):
    if not phone.startswith('+'):
        phone = '+' + phone.lstrip('0')

    valid, country, network, tzones = "Unknown", "Unknown", "Unknown", ""
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone
        try:
            parsed = phonenumbers.parse(phone, None)
            valid = "YES" if phonenumbers.is_valid_number(parsed) else "NO (Invalid Format)"
            country = geocoder.description_for_number(parsed, "en") or "Unknown"
            network = carrier.name_for_number(parsed, "en") or "Unknown"
            tzones = ", ".join(timezone.time_zones_for_number(parsed))
        except Exception:
            valid = "INVALID PARSE"
    except ImportError:
        valid = "Module Error"
        
    color = GREEN if valid == "YES" else RED
    clean_phone = phone.replace("+", "")
    dork_1 = f'intext:"{phone}" OR intext:"{clean_phone}"'
    dork_2 = f'ext:txt OR ext:csv "{phone}"'

    EXPORT_DATA.append({
        "Target": phone, "Type": "Phone", "Status": valid,
        "Leaks": "N/A", "Details": f"Country: {country} | Carrier: {network}"
    })

    if quiet:
        print(f"{phone} | Valid: {valid} | Country: {country} | Carrier: {network}")
        return
        
    lines = [
        f"{WHITE}• Target     :{RESET} {phone}",
        f"{WHITE}• Valid      :{RESET} {color}{BOLD}{valid}{RESET}",
    ]
    
    if valid == "YES":
        lines.extend([
            f"{WHITE}• Country    :{RESET} {country}",
            f"{WHITE}• Carrier    :{RESET} {YELLOW}{network}{RESET}",
            f"{WHITE}• Timezone   :{RESET} {tzones}",
            f"{WHITE}• OSINT Dork :{RESET} {CYAN}{dork_1}{RESET}",
            f"{WHITE}• Leak Search:{RESET} {CYAN}{dork_2}{RESET}"
        ])
         
    print_box("PHONE OSINT ANALYSIS", lines, color=color if valid == "YES" else RED)

# --- Pentest Features ---

def identify_hash(hash_str: str):
    length = len(hash_str)
    is_hex = all(c in string.hexdigits for c in hash_str)
    
    types = []
    if hash_str.startswith('$1$'): types.append("MD5 Crypt")
    elif hash_str.startswith('$2'): types.append("Bcrypt (Blowfish)")
    elif hash_str.startswith('$5$'): types.append("SHA-256 Crypt")
    elif hash_str.startswith('$6$'): types.append("SHA-512 Crypt")
    elif is_hex:
        if length == 32: types.extend(["MD5", "NTLM"])
        elif length == 40: types.append("SHA-1")
        elif length == 64: types.append("SHA-256")
        elif length == 128: types.append("SHA-512")
    
    if not types: types.append("Unknown or Custom Hash")
    print_box("HASH IDENTIFIER", [
        f"{WHITE}• Hash       :{RESET} {hash_str[:40]}...",
        f"{WHITE}• Length     :{RESET} {length} chars",
        f"{WHITE}• Possible   :{RESET} {YELLOW}{', '.join(types)}{RESET}"
    ], color=MAGENTA)

def mutate_word(base_word: str, output_file: str = None):
    subs = {'a': '@', 'i': '1', 'e': '3', 'o': '0', 's': '$'}
    current_year = "2026"
    suffixes = ['', '123', '!', '@', f'{current_year}', f'{current_year}!']
    
    base_variations = [base_word.lower(), base_word.title(), base_word.upper()]
    mutated = set()
    
    for word in base_variations:
        for suf in suffixes:
            mutated.add(f"{word}{suf}")
            leet = "".join(subs.get(c.lower(), c) for c in word)
            mutated.add(f"{leet}{suf}")
            
    mutated_list = sorted(list(mutated))
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write("\n".join(mutated_list))
        print(f"{GREEN}[✓] Generated {len(mutated_list)} mutations saved to {output_file}{RESET}")
    else:
        print_box(f"WORDLIST MUTATOR ({len(mutated_list)} Words)", 
                  [f"{WHITE}• Samples    :{RESET} {', '.join(mutated_list[:8])}..."], color=CYAN)

def export_csv(filename: str):
    if not EXPORT_DATA: return
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["Target", "Type", "Status", "Leaks", "Details"])
            writer.writeheader()
            writer.writerows(EXPORT_DATA)
        print(f"\n{GREEN}[✓] Report successfully exported to {BOLD}{filename}{RESET}")
    except Exception as e:
        print(f"{RED}[✗] Error saving CSV: {e}{RESET}")

# --- CLI Setup & Help ---

class CustomHelpFormatter(argparse.HelpFormatter):
    def format_help(self):
        return f"{BANNER}\n" \
               f"{DIM}mrpass: Advanced OSINT & Security Analysis Tool{RESET}\n\n" \
               f"{BOLD}SYNTAX:{RESET}\n" \
               f"  mrpass [TARGET] [OPTIONS]\n\n" \
               f"{BOLD}TARGET MODES:{RESET}\n" \
               f"  {GREEN}-ps, --password{RESET}       Analyze password strength, entropy, and crack time\n" \
               f"  {GREEN}-em, --email{RESET}          Investigate email addresses for breaches and disposable status\n" \
               f"  {GREEN}-ph, --phone{RESET}          Analyze phone numbers (Carrier, Country, OSINT Dorks)\n" \
               f"  {GREEN}-id, --identify{RESET}       Identify unknown hash types (MD5, SHA, NTLM, etc.)\n" \
               f"  {GREEN}-m,  --mutate [FILE]{RESET}  Generate a custom pentest wordlist from a base target word\n" \
               f"  {GREEN}-n,  --new [LENGTH]{RESET}   Generate a secure random password (default length: 16)\n\n" \
               f"{BOLD}OSINT & FILE OPERATIONS:{RESET}\n" \
               f"  {GREEN}-sr, --search-leak{RESET}    Query threat intel APIs (HaveIBeenPwned, XposedOrNot, Debounce)\n" \
               f"  {GREEN}-f,  --file [FILE]{RESET}    Bulk scan mode: Read multiple targets from a text file\n" \
               f"  {GREEN}-o,  --output [FILE]{RESET}  Export all scan results to a formatted CSV file\n" \
               f"  {GREEN}-q,  --quiet{RESET}          Stealth/Automation mode: Suppress banners and UI formatting\n" \
               f"  {GREEN}-h,  --help{RESET}           Show this advanced help menu\n\n" \
               f"{BOLD}REAL-WORLD EXAMPLES:{RESET}\n" \
               f"  {YELLOW}1. OSINT Password Scan:{RESET}  mrpass \"Admin@123\" -ps -sr\n" \
               f"  {YELLOW}2. Email Breach Check :{RESET}  mrpass \"target@mail.com\" -em -sr\n" \
               f"  {YELLOW}3. Phone Number OSINT :{RESET}  mrpass \"+2010xxxxxxxx\" -ph\n" \
               f"  {YELLOW}4. Hash Identification:{RESET}  mrpass \"5d41402abc...\" -id\n" \
               f"  {YELLOW}5. Bulk Scan & Export :{RESET}  mrpass -f targets.txt -ps -sr -o report.csv\n"

def main():
    parser = argparse.ArgumentParser(formatter_class=CustomHelpFormatter, add_help=False)
    parser.add_argument('target', nargs='?', help=argparse.SUPPRESS)
    parser.add_argument('-ps', '--password', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-em', '--email', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-ph', '--phone', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-sr', '--search-leak', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-id', '--identify', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-m', '--mutate', nargs='?', const='console', type=str, help=argparse.SUPPRESS)
    parser.add_argument('-n', '--new', nargs='?', const=16, type=int, help=argparse.SUPPRESS)
    parser.add_argument('-f', '--file', type=str, help=argparse.SUPPRESS)
    parser.add_argument('-o', '--output', type=str, help=argparse.SUPPRESS)
    parser.add_argument('-q', '--quiet', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-h', '--help', action='help', help=argparse.SUPPRESS)

    if len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        sys.exit(1)

    try: args = parser.parse_args()
    except SystemExit: return

    if args.target == 'info':
        if not args.quiet: print(BANNER)
        print_box("DEVELOPER INFO & TOOL SPECS", [
            f"{WHITE}▸ Author      :{RESET} Mahmoud Ramadan Elbezzawy",
            f"{WHITE}▸ Academic    :{RESET} Computer Science & AI (Cybersecurity Focus)",
            f"{WHITE}▸ GitHub      :{RESET} github.com/mahmoudramadan06",
            f"{WHITE}▸ LinkedIn    :{RESET} linkedin.com/in/mahmoud-r-elbezzawy",
            f"{WHITE}▸ Description :{RESET} A standalone, high-performance CLI tool designed",
            f"{WHITE}                {RESET} for Penetration Testers and Security Analysts.",
            f"{WHITE}▸ Core Modules:{RESET} - Advanced Password Entropy Analyzer",
            f"{WHITE}                {RESET} - OSINT Breach Integration (HIBP & XON)",
            f"{WHITE}                {RESET} - Phone Number Analysis & OSINT Dorking",
            f"{WHITE}                {RESET} - Hash Type Identifier & Wordlist Mutator"
        ], width=85, color=BLUE, quiet=args.quiet)
        return

    if args.new:
        pwd = generate_strong_password(args.new)
        metrics = calculate_metrics(pwd)
        if args.quiet:
            print(pwd)
        else:
            print_box("SECURE GENERATOR", [
                f"{WHITE}• Generated  :{RESET} {GREEN}{BOLD}{pwd}{RESET}",
                f"{WHITE}• Length     :{RESET} {args.new} characters",
                f"{WHITE}• ETA Crack  :{RESET} {YELLOW}{BOLD}{metrics['time']}{RESET}",
            ], color=GREEN)
        return

    if args.identify and args.target:
        identify_hash(args.target)
        return

    if args.mutate and args.target:
        out_file = None if args.mutate == 'console' else args.mutate
        mutate_word(args.target, out_file)
        return

    targets = []
    if args.target: targets.append(args.target)
    if args.file:
        if os.path.isfile(args.file):
            with open(args.file, 'r', encoding='utf-8') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        else:
            print(f"{RED}[✗] Error: File '{args.file}' not found.{RESET}")
            sys.exit(1)

    if not targets:
        print(f"{YELLOW}[!] No target provided. Run 'mrpass -h' for usage guide.{RESET}")
        return

    for t in targets:
        if args.password: analyze_password(t, args.search_leak, args.quiet)
        elif args.email: analyze_email(t, args.search_leak, args.quiet)
        elif args.phone: analyze_phone(t, args.quiet)
        else: print(f"{RED}[✗] Missing target mode flag (-ps, -em, or -ph).{RESET}"); return

    if args.output: export_csv(args.output)

if __name__ == "__main__":
    main()