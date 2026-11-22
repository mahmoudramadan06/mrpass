#!/usr/bin/env python3
"""mrpass v4 test suite.

Runs fully offline with stdlib unittest:
    python -m unittest discover -s tests -v

Live API tests (HIBP, XposedOrNot, debounce, DoH) only run when:
    MRPASS_NET_TESTS=1 python -m unittest discover -s tests -v
"""

import csv
import io
import json
import math
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mrpass  # noqa: E402

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
MRPASS_PY = os.path.join(REPO_ROOT, "mrpass.py")
NET = os.environ.get("MRPASS_NET_TESTS") == "1"


def run_cli(args, stdin_text=None, timeout=30):
    env = dict(os.environ, NO_COLOR="1")
    return subprocess.run(
        [sys.executable, MRPASS_PY, *args],
        input=stdin_text, capture_output=True, text=True, timeout=timeout, env=env,
    )


class TestPatternDetection(unittest.TestCase):
    def test_repeats(self):
        self.assertTrue(any("repeated characters" in f for f in mrpass.detect_patterns("Baaad!!999")))
        self.assertFalse(any("repeated characters" in f for f in mrpass.detect_patterns("Tr7$kM9!qW2z")))

    def test_repeated_chunk(self):
        self.assertTrue(any("repeated chunk" in f for f in mrpass.detect_patterns("abcabc12")))

    def test_sequence(self):
        self.assertTrue(any("sequential" in f for f in mrpass.detect_patterns("Xabcd9!")))
        self.assertTrue(any("sequential" in f for f in mrpass.detect_patterns("z4321!Q")))

    def test_keyboard_walk(self):
        self.assertTrue(any("keyboard" in f for f in mrpass.detect_patterns("qwerty99!")))
        self.assertTrue(any("keyboard" in f for f in mrpass.detect_patterns("1qaz@WSX")))

    def test_year(self):
        self.assertTrue(any("year" in f for f in mrpass.detect_patterns("Secure2026!")))

    def test_dictionary_leet(self):
        self.assertTrue(any("dictionary" in f for f in mrpass.detect_patterns("p@ssw0rd")))
        self.assertTrue(any("dictionary" in f for f in mrpass.detect_patterns("P@ssw0rd99")))
        self.assertTrue(any("dictionary" in f for f in mrpass.detect_patterns("dr@g0n")))

    def test_clean_password_no_findings(self):
        findings = mrpass.detect_patterns("Tr7$kM9!qW2zXp4#")
        self.assertEqual(findings, [], f"unexpected findings: {findings}")

    def test_keyboard_walk_long_inputs_stay_fast(self):
        import time as _t
        big = "xQ9!" * 2500  # 10k chars, no walks
        start = _t.monotonic()
        mrpass.detect_patterns(big)
        elapsed = _t.monotonic() - start
        self.assertLess(elapsed, 2.0, f"pattern detection took {elapsed:.2f}s on 10k chars")
        # A long walk embedded deep in a long string is still caught.
        self.assertTrue(any("keyboard" in f for f in mrpass.detect_patterns("x" * 2000 + "asdfghjkl" + "y" * 2000)))


class TestMetrics(unittest.TestCase):
    def test_entropy_math(self):
        m = mrpass.password_metrics("aaaaaaaa")  # 8 lowercase
        self.assertEqual(m["charset_space"], 26)
        self.assertAlmostEqual(m["entropy"], 8 * math.log2(26), places=6)

    def test_full_charset_space(self):
        m = mrpass.password_metrics("aA1!bB2@")
        self.assertEqual(m["charset_space"], 94)
        self.assertEqual(m["classes"], 4)

    def test_common_password_scores_zero(self):
        self.assertEqual(mrpass.password_metrics("password")["score"], 0)
        self.assertEqual(mrpass.password_metrics("P@ssw0rd")["score"], 0)

    def test_strong_password_scores_high(self):
        m = mrpass.password_metrics(mrpass.generate_password(24))
        self.assertGreaterEqual(m["score"], 3)

    def test_pattern_penalty_applies(self):
        clean = mrpass.password_metrics("Kx9#mQ2$vL8!")
        walked = mrpass.password_metrics("Kx9#mQ2$vL8!qwerty")
        self.assertLessEqual(walked["score"], clean["score"] + 1)  # longer but penalized

    def test_very_long_password_no_overflow(self):
        m = mrpass.password_metrics("Xa9!" * 40)  # 160 chars
        self.assertTrue(all(isinstance(v, str) for v in m["crack_times"].values()))
        self.assertIn("years", m["crack_times"]["offline fast hash (GPU, 100B/s)"])

    def test_crack_time_scenarios_present(self):
        m = mrpass.password_metrics("SomePass123!")
        self.assertEqual(len(m["crack_times"]), 3)
        self.assertTrue(all(isinstance(v, str) for v in m["crack_times"].values()))


class TestGenerator(unittest.TestCase):
    def test_default_length_and_classes(self):
        pw = mrpass.generate_password()
        self.assertEqual(len(pw), 16)
        for pred in (str.islower, str.isupper, str.isdigit):
            self.assertTrue(any(pred(c) for c in pw))
        self.assertTrue(any(not c.isalnum() for c in pw))

    def test_short_length_raises_not_hangs(self):
        with self.assertRaises(ValueError):
            mrpass.generate_password(3)  # v3 hung forever here
        with self.assertRaises(ValueError):
            mrpass.generate_password(0)
        with self.assertRaises(ValueError):
            mrpass.generate_password(-5)

    def test_no_symbols_alnum_only(self):
        pw = mrpass.generate_password(32, use_symbols=False)
        self.assertTrue(pw.isalnum())
        with self.assertRaises(ValueError):
            mrpass.generate_password(2, use_symbols=False)

    def test_avoid_ambiguous(self):
        for _ in range(50):
            pw = mrpass.generate_password(16, avoid_ambiguous=True)
            self.assertFalse(set(pw) & set("Il1O0"))

    def test_uniqueness(self):
        samples = {mrpass.generate_password() for _ in range(200)}
        self.assertEqual(len(samples), 200)

    def test_passphrase(self):
        phrase = mrpass.generate_passphrase(6, separator=".")
        parts = phrase.split(".")
        self.assertEqual(len(parts), 6)
        self.assertTrue(all(p in mrpass.EFF_WORDS for p in parts))

    def test_passphrase_capitalize(self):
        phrase = mrpass.generate_passphrase(4, capitalize=True)
        self.assertTrue(all(w[0].isupper() for w in phrase.split("-")))

    def test_passphrase_errors(self):
        with self.assertRaises(ValueError):
            mrpass.generate_passphrase(0)


class TestMasking(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(mrpass.mask_secret("Str0ng!Pass"), "S*********s")
        self.assertEqual(mrpass.mask_secret("abc"), "***")
        self.assertEqual(mrpass.mask_secret(""), "")

    def test_no_password_derived_hashes_in_outputs(self):
        # An unsalted digest of an analyzed password is offline verification
        # material: it must never appear in results, exports or display.
        mrpass.RESULTS.clear()
        mrpass.EXPORT_DATA.clear()
        with redirect_stdout(io.StringIO()) as buf:
            mrpass.analyze_password("Str0ng!Passw0rdXYZ", check_online=False, quiet=False)
        import hashlib as _hl
        digest = _hl.sha256(b"Str0ng!Passw0rdXYZ").hexdigest()
        self.assertNotIn(digest[:12], buf.getvalue())
        self.assertNotIn("sha256_12", json.dumps(mrpass.RESULTS))
        self.assertNotIn(digest[:12], json.dumps(mrpass.EXPORT_DATA))



class TestHumanTime(unittest.TestCase):
    def test_ranges(self):
        self.assertEqual(mrpass.human_time(0.5), "Instantly")
        self.assertIn("minutes", mrpass.human_time(300))
        self.assertIn("hours", mrpass.human_time(7200))
        self.assertIn("days", mrpass.human_time(200000))
        self.assertIn("years", mrpass.human_time(10 ** 10))
        self.assertIn("e", mrpass.human_time(10 ** 24))  # scientific for huge values


class TestHashIdentification(unittest.TestCase):
    CASES = [
        ("5d41402abc4b2a76b9719d911017c592", "MD5 / NTLM / LM"),
        ("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "SHA-1 / RIPEMD-160"),
        ("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", "SHA-256 / SHA3-256 / BLAKE2s"),
        ("a" * 96, "SHA-384 / SHA3-384"),
        ("b" * 128, "SHA-512 / SHA3-512 / BLAKE2b"),
        ("d" * 56, "SHA-224"),
        ("c" * 8, "CRC-32"),
        ("$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", "bcrypt"),
        ("$1$salt$qJH7.N4xYta3aEG/dfqo/0", "md5crypt"),
        ("$6$rounds=5000$saltsalt$" + "A" * 86, "sha512crypt"),
        ("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG", "Argon2"),
        ("$P$984478476IagS59wHZvyQMArzfx58u.", "phpass (WordPress/phpBB)"),
        ("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", "MySQL 4.1+ (SHA-1)"),
        ("{SSHA}AzKxS7ws2OY1OKvGDQzKz0+b8FGHMTM2", "LDAP SSHA (salted SHA-1)"),
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "JWT (JSON Web Token)"),
        ("pbkdf2_sha256$600000$saltsalt$" + "aB9/" * 11 + "aB8=", "Django PBKDF2-SHA256"),
    ]

    def test_known_samples(self):
        for sample, expected_name in self.CASES:
            with self.subTest(expected=expected_name):
                names = [n for n, rx, _, _, _ in mrpass.HASH_PATTERNS if rx.match(sample.strip())]
                self.assertIn(expected_name, names, f"got {names}")

    def test_unknown(self):
        names = [n for n, rx, _, _, _ in mrpass.HASH_PATTERNS if rx.match("!!!not-a-hash!!!")]
        self.assertEqual(names, [])

    def test_all_patterns_have_name(self):
        for name, rx, hc, john, note in mrpass.HASH_PATTERNS:
            self.assertTrue(name)
            self.assertTrue(rx.pattern)


class TestMutator(unittest.TestCase):
    def test_basic_count_and_dedupe(self):
        out = mrpass.mutate_words(["password"], years=[2026], level=1)
        self.assertEqual(len(out), len(set(out)))
        self.assertIn("password", out)
        self.assertIn("Password2026", out)
        self.assertIn("PASSWORD!", out)
        self.assertIn("p@$$w0rd123", out)  # leet variant

    def test_no_leet(self):
        out = mrpass.mutate_words(["password"], years=[2026], level=1, use_leet=False)
        self.assertFalse(any("@" in w or "$" in w for w in out))

    def test_levels_grow(self):
        counts = [len(mrpass.mutate_words(["test"], years=[2026], level=lvl)) for lvl in (1, 2, 3)]
        self.assertLess(counts[0], counts[1])
        self.assertLess(counts[1], counts[2])

    def test_min_max_length(self):
        out = mrpass.mutate_words(["pass"], years=[2026], level=2, min_len=6, max_len=8)
        self.assertTrue(all(6 <= len(w) <= 8 for w in out))

    def test_multiple_words(self):
        out = mrpass.mutate_words(["alpha", "beta"], years=[2026], level=1)
        self.assertTrue(any(w.startswith("alpha") for w in out))
        self.assertTrue(any(w.startswith("beta") for w in out))

    def test_years_parser(self):
        self.assertEqual(mrpass.parse_years("2024"), [2024])
        self.assertEqual(mrpass.parse_years("2020-2023"), [2020, 2021, 2022, 2023])
        self.assertEqual(mrpass.parse_years("2023-2020"), [2020, 2021, 2022, 2023])
        with self.assertRaises(ValueError):
            mrpass.parse_years("abc")
        with self.assertRaises(ValueError):
            mrpass.parse_years("1900-2100")


class TestEmail(unittest.TestCase):
    def test_syntax(self):
        self.assertTrue(mrpass.EMAIL_RE.match("user@example.com"))
        self.assertTrue(mrpass.EMAIL_RE.match("u.ser+tag@sub.domain.co"))
        self.assertFalse(mrpass.EMAIL_RE.match("not-an-email"))
        self.assertFalse(mrpass.EMAIL_RE.match("a@b"))
        self.assertFalse(mrpass.EMAIL_RE.match("@x.com"))

    def test_local_disposable_list(self):
        self.assertEqual(mrpass.check_email_disposable.__name__, "check_email_disposable")
        self.assertIn("mailinator.com", mrpass.DISPOSABLE_DOMAINS)

    def test_offline_analysis_never_calls_network(self):
        mrpass.RESULTS.clear()
        with redirect_stdout(io.StringIO()):
            mrpass.analyze_email("user@example.com", check_online=False, quiet=True)
        res = mrpass.RESULTS[-1]
        self.assertTrue(res["syntax_valid"])
        self.assertIsNone(res["breaches"])
        self.assertIn("NOT CHECKED", res["status"])


class TestPhone(unittest.TestCase):
    def setUp(self):
        mrpass.set_colors(False)

    # Fixture is the documentation example number used by libphonenumber's own
    # test suite (Google HQ switchboard) - never a real person's private number.
    DOC_NUMBER = "+16502530000"

    def test_valid_documented_number(self):
        mrpass.RESULTS.clear()
        with redirect_stdout(io.StringIO()):
            mrpass.analyze_phone(self.DOC_NUMBER, quiet=True)
        res = mrpass.RESULTS[-1]
        self.assertTrue(res["valid"])
        self.assertEqual(res["region"], "US")
        self.assertIn("Mountain View", res["country"])
        self.assertEqual(res["e164"], self.DOC_NUMBER)
        self.assertIn("line_type", res)

    def test_adds_missing_plus(self):
        mrpass.RESULTS.clear()
        with redirect_stdout(io.StringIO()):
            mrpass.analyze_phone(self.DOC_NUMBER.lstrip("+"), quiet=True)
        self.assertTrue(mrpass.RESULTS[-1]["valid"])

    def test_invalid_number(self):
        mrpass.RESULTS.clear()
        with redirect_stdout(io.StringIO()):
            mrpass.analyze_phone("+20123", quiet=True)
        res = mrpass.RESULTS[-1]
        self.assertFalse(res["valid"])

    def test_garbage(self):
        mrpass.RESULTS.clear()
        with redirect_stdout(io.StringIO()):
            mrpass.analyze_phone("hello world", quiet=True)
        self.assertFalse(mrpass.RESULTS[-1]["valid"])


class TestCLI(unittest.TestCase):
    def test_version(self):
        r = run_cli(["--version"])
        self.assertEqual(r.returncode, 0)
        self.assertIn(mrpass.VERSION, r.stdout)

    def test_no_args_exits_1_with_help(self):
        r = run_cli([])
        self.assertEqual(r.returncode, 1)
        self.assertIn("SYNTAX", r.stdout)

    def test_unknown_flag_exits_2(self):
        r = run_cli(["--definitely-not-a-flag"])
        self.assertEqual(r.returncode, 2)

    def test_password_analysis_masks_target(self):
        secret = "Str0ng!Passw0rdXYZ"
        r = run_cli([secret, "-ps"])
        self.assertEqual(r.returncode, 0)
        self.assertNotIn(secret, r.stdout, "password leaked into output")
        self.assertIn(mrpass.mask_secret(secret), r.stdout)
        self.assertIn("PASSWORD ANALYSIS", r.stdout)

    def test_password_from_stdin(self):
        secret = "Str0ng!Passw0rdXYZ"
        r = run_cli(["-ps", "-q"], stdin_text=secret + "\n")
        self.assertEqual(r.returncode, 0)
        self.assertNotIn(secret, r.stdout)

    def test_json_mode_valid(self):
        r = run_cli(["SomePass!2026x", "-ps", "--json"])
        self.assertEqual(r.returncode, 0)
        data = json.loads(r.stdout)
        self.assertEqual(data["mrpass_version"], mrpass.VERSION)
        self.assertEqual(data["results"][0]["type"], "password")
        self.assertNotIn("SomePass!2026x", r.stdout)

    def test_generate_short_fails_fast(self):
        # v3 hung forever on -n 3; v4 must exit 2 quickly.
        r = run_cli(["-n", "3"], timeout=10)
        self.assertEqual(r.returncode, 2)
        self.assertIn("too short", r.stderr)

    def test_generate_ok(self):
        r = run_cli(["-n", "20"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("SECURE GENERATOR", r.stdout)

    def test_passphrase_cli(self):
        r = run_cli(["-pp", "6", "-q"])
        self.assertEqual(r.returncode, 0)
        words = r.stdout.strip().split("-")
        self.assertEqual(len(words), 6)
        self.assertTrue(all(w in mrpass.EFF_WORDS for w in words))

    def test_identify(self):
        r = run_cli(["5d41402abc4b2a76b9719d911017c592", "-id"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("MD5", r.stdout)

    def test_mutate_console_and_file(self):
        r = run_cli(["secureword", "-m"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("WORDLIST MUTATOR", r.stdout)
        out_path = os.path.join(REPO_ROOT, "tests", "_tmp_wordlist.txt")
        try:
            r = run_cli(["secureword", "-m", out_path, "--level", "1"])
            self.assertEqual(r.returncode, 0)
            with open(out_path) as f:
                lines = [l.strip() for l in f if l.strip()]
            self.assertGreater(len(lines), 20)
            self.assertIn("secureword", lines)
        finally:
            if os.path.exists(out_path):
                os.unlink(out_path)

    def test_mutate_requires_target(self):
        r = run_cli(["-m"])
        self.assertEqual(r.returncode, 1)

    def test_bulk_csv_export_masks_secrets(self):
        targets = os.path.join(REPO_ROOT, "tests", "_tmp_targets.txt")
        csv_path = os.path.join(REPO_ROOT, "tests", "_tmp_report.csv")
        secret = "Str0ng!Passw0rdXYZ"
        try:
            with open(targets, "w") as f:
                f.write(secret + "\nhello123\n")
            r = run_cli(["-f", targets, "-ps", "-q", "-o", csv_path])
            self.assertEqual(r.returncode, 0)
            with open(csv_path) as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)
            blob = open(csv_path).read()
            self.assertNotIn(secret, blob, "CSV leaked plaintext password")
            self.assertNotIn("sha256", blob, "CSV must not store password-derived hashes")
            self.assertIn(mrpass.mask_secret(secret), blob)
        finally:
            for p in (targets, csv_path):
                if os.path.exists(p):
                    os.unlink(p)

    def test_file_not_found_exit_1(self):
        r = run_cli(["-f", "no_such_file_xyz.txt", "-ps"])
        self.assertEqual(r.returncode, 1)

    def test_email_offline(self):
        r = run_cli(["user@example.com", "-em"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("EMAIL OSINT", r.stdout)
        self.assertIn("NOT CHECKED", r.stdout)

    def test_phone_cli(self):
        r = run_cli(["+16502530000", "-ph", "-q"])  # libphonenumber doc fixture
        self.assertEqual(r.returncode, 0)
        self.assertIn("Valid: YES", r.stdout)

    def test_json_plus_csv_stdout_stays_valid_json(self):
        csv_path = os.path.join(REPO_ROOT, "tests", "_tmp_j.csv")
        try:
            r = run_cli(["SomePass!2026x", "-ps", "--json", "-o", csv_path])
            self.assertEqual(r.returncode, 0)
            json.loads(r.stdout)  # must parse: export message goes to stderr
            self.assertTrue(os.path.exists(csv_path))
        finally:
            if os.path.exists(csv_path):
                os.unlink(csv_path)

    def test_csv_formula_injection_neutralized(self):
        mrpass.EXPORT_DATA.clear()
        mrpass.RESULTS.clear()
        csv_path = os.path.join(REPO_ROOT, "tests", "_tmp_inj.csv")
        try:
            with redirect_stdout(io.StringIO()):
                mrpass.analyze_password("=HYPERLINK(x)", check_online=False, quiet=True)
                mrpass.analyze_password("-trail1ng", check_online=False, quiet=True)
                mrpass.analyze_password("+plus1234", check_online=False, quiet=True)
                self.assertTrue(mrpass.export_csv(csv_path))
            blob = open(csv_path).read()
            for line in blob.splitlines()[1:]:
                first_cell = line.split(",", 1)[0]
                self.assertTrue(first_cell.startswith("'"), f"unsafe cell: {first_cell!r}")
        finally:
            if os.path.exists(csv_path):
                os.unlink(csv_path)

    def test_csv_export_failure_exit_1(self):
        r = run_cli(["SomePass!2026x", "-ps", "-q", "-o", "/nonexistent_dir_xyz/report.csv"])
        self.assertEqual(r.returncode, 1)

    def test_generation_only_with_export_warns_but_exits_0(self):
        # Generation produces no analysis records: warn, but it is not a failure.
        r = run_cli(["-n", "16", "-q", "-o", "/tmp/_gen_only_should_not_exist.csv"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("Nothing to export", r.stdout + r.stderr)
        self.assertFalse(os.path.exists("/tmp/_gen_only_should_not_exist.csv"))

    def test_bad_years_exit_2(self):
        r = run_cli(["word", "-m", "--years", "garbage"])
        self.assertEqual(r.returncode, 2)


class TestHibpRetry(unittest.TestCase):
    def test_retries_on_429_then_succeeds(self):
        from unittest import mock
        ok = mock.Mock(status_code=200, text="1E2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:7\n")
        limited = mock.Mock(status_code=429)
        with mock.patch.object(mrpass.requests, "get", side_effect=[limited, ok]) as g, \
             mock.patch.object(mrpass.time, "sleep") as s:
            count, err = mrpass.check_password_hibp("x" * 40)
        self.assertIsNone(err)
        self.assertEqual(g.call_count, 2)
        s.assert_called_once()

    def test_persistent_429_reports_error(self):
        from unittest import mock
        limited = mock.Mock(status_code=429)
        with mock.patch.object(mrpass.requests, "get", return_value=limited), \
             mock.patch.object(mrpass.time, "sleep"):
            count, err = mrpass.check_password_hibp("x" * 40)
        self.assertIsNone(count)
        self.assertIn("429", err)

    def test_network_exception(self):
        from unittest import mock
        with mock.patch.object(mrpass.requests, "get",
                               side_effect=mrpass.requests.ConnectionError("down")):
            count, err = mrpass.check_password_hibp("x" * 40)
        self.assertIsNone(count)
        self.assertIn("network error", err)


@unittest.skipUnless(NET, "live API tests disabled (set MRPASS_NET_TESTS=1)")
class TestLiveAPIs(unittest.TestCase):
    def test_hibp_known_pwned(self):
        count, err = mrpass.check_password_hibp("password")
        self.assertIsNone(err)
        self.assertIsNotNone(count)
        self.assertGreater(count, 1000)

    def test_hibp_random_clean(self):
        count, err = mrpass.check_password_hibp("zQ9!" + os.urandom(12).hex())
        self.assertIsNone(err)
        self.assertEqual(count, 0)

    def test_xon_shape(self):
        breaches, err = mrpass.check_email_xon("test@example.com")
        self.assertIsNone(err)
        self.assertIsInstance(breaches, list)
        self.assertTrue(all(isinstance(b, str) for b in breaches))

    def test_debounce(self):
        disp, err = mrpass.check_email_disposable("x@mailinator.com")
        self.assertTrue(disp)
        disp2, err2 = mrpass.check_email_disposable("someone@example.com")  # RFC 2606 reserved
        if err2 is None:
            self.assertFalse(disp2)

    def test_mx(self):
        has_mx, err = mrpass.check_mx("gmail.com")
        self.assertIsNone(err)
        self.assertTrue(has_mx)
        has_mx2, _ = mrpass.check_mx("nonexistent-domain-zzz-12345.invalid")
        self.assertFalse(has_mx2)


if __name__ == "__main__":
    unittest.main()
