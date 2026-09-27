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
import shutil
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Iterable, Optional

# Public-safe default: Admin is locked unless a key hash is provided by env.
LOCAL_DEFAULT_ADMIN_CODE_SHA256 = ""
CURRENT_VERSION = "v0.4.0"
USER_AGENT = "curl/8.0 HXSecurity-Terminal/0.4"
RELEASE_API_URL = "https://api.github.com/repos/Afterhoursmc-gg/hxsecurity-terminal/releases/latest"
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
TEST4_SUCCESS_TEXT = "TEST 4 SUCCESS, SERVICE MAP COMPLETE!"
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

    def request_json(self, url: str) -> object:
        res = self.request(url)
        if res.status != 200:
            raise RuntimeError(f"HTTP {res.status} from {url}")
        return json.loads(res.text)

    def check_for_update(self, apply: bool = False) -> bool:
        print(f"[update] current version: {CURRENT_VERSION}")
        try:
            data = self.request_json(RELEASE_API_URL)
            latest = str(data.get("tag_name") or "")
            assets = data.get("assets") or []
            asset_url = None
            for asset in assets:
                if asset.get("name") == "hxsecurity_terminal.py":
                    asset_url = asset.get("browser_download_url")
                    break
        except Exception as exc:
            print(f"[update] failed to check latest release: {exc}")
            return False
        if not latest or not asset_url:
            print("[update] latest release does not include hxsecurity_terminal.py")
            return False
        print(f"[update] latest version: {latest}")
        if latest == CURRENT_VERSION or not release_is_newer(latest, CURRENT_VERSION):
            print("[update] already up to date")
            return False
        print(f"[update] update available: {CURRENT_VERSION} -> {latest}")
        print(f"[update] download: {asset_url}")
        if not apply:
            print("[update] choose Admin menu option 5 to install the update")
            return True
        current = Path(__file__).resolve()
        with tempfile.NamedTemporaryFile("wb", delete=False, suffix=".py") as tmp:
            tmp_path = Path(tmp.name)
            req = urllib.request.Request(asset_url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                tmp.write(resp.read())
        compile(tmp_path.read_text(encoding="utf-8"), str(tmp_path), "exec")
        backup = current.with_suffix(current.suffix + f".{CURRENT_VERSION}.bak")
        shutil.copy2(current, backup)
        shutil.copy2(tmp_path, current)
        os.chmod(current, 0o755)
        try:
            tmp_path.unlink()
        except OSError:
            pass
        print(f"[update] installed {latest}")
        print(f"[update] backup: {backup}")
        print("[update] restart the terminal to use the new version")
        return True

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


    def run_test4_auto(self, start_url: str) -> bool:
        base_url = normalize_base_url(start_url)
        assert_allowed_target(base_url)
        print(f"[test4] target: {base_url}")
        print("[test4] tracing sitemap/status/manifest/archive chain...")
        login_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", "test4/login")
        login = self.request(login_url)
        release = header_get(login.headers, "x-hx-release")
        if login.status != 200 or not release:
            print(f"[test4] missing Test 4 login/header clue; status={login.status}")
            return False
        print("[test4] login/header clue recovered")
        sitemap_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", "sitemap.xml")
        sitemap = self.request(sitemap_url)
        if sitemap.status != 200:
            print(f"[test4] sitemap unavailable; status={sitemap.status}")
            return False
        status_paths = []
        for match in re.findall(r"https?://[^<\s]+|/[-A-Za-z0-9_./]+", sitemap.text):
            parsed_path = urllib.parse.urlparse(match).path if match.startswith("http") else match
            if parsed_path.startswith("/test4/status/"):
                status_paths.append(parsed_path)
        if not status_paths:
            print("[test4] no Test 4 status path found in sitemap")
            return False
        print("[test4] sitemap clue recovered")
        status_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", status_paths[0].lstrip("/"))
        status = self.request(status_url)
        if status.status != 200:
            print(f"[test4] status JSON unavailable; status={status.status}")
            return False
        try:
            status_data = json.loads(status.text)
        except Exception:
            print("[test4] status body is not JSON")
            return False
        manifest_path = status_data.get("deployManifest")
        if not isinstance(manifest_path, str) or not manifest_path.startswith("/test4/"):
            print("[test4] no deploy manifest in status JSON")
            return False
        print("[test4] status JSON clue recovered")
        manifest_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", manifest_path.lstrip("/"))
        manifest = self.request(manifest_url)
        if manifest.status != 200:
            print(f"[test4] manifest unavailable; status={manifest.status}")
            return False
        artifact_paths = [p for p in PATH_RE.findall(manifest.text) if p.startswith("/test4/") and ("bak" in p or "env" in p or "config" in p)]
        if not artifact_paths:
            print("[test4] no archived env/config artifact path found in manifest")
            return False
        print("[test4] manifest clue recovered")
        secret = None; secret_key = None; artifact_url = None
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
            print("[test4] no Base64 credential marker found in chained artifact")
            return False
        print(f"[test4] credential marker found: {secret_key}")
        print(f"[test4] sitemap URL: {sitemap_url}")
        print(f"[test4] status URL: {status_url}")
        print(f"[test4] manifest URL: {manifest_url}")
        print(f"[test4] artifact URL: {artifact_url}")
        print("[test4] decoded credential recovered")
        print("[test4] recovered username: admin")
        print(f"[test4] recovered password: {secret}")
        body = urllib.parse.urlencode({"username": "admin", "password": secret}).encode()
        res = self.request(login_url, method="POST", data=body)
        if TEST4_SUCCESS_TEXT in res.text:
            print(TEST4_SUCCESS_TEXT)
            return True
        print(f"[test4] login did not reach success page; status={res.status} size={res.size}")
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


def version_tuple(tag: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", tag)
    return tuple(int(n) for n in nums[:3]) if nums else (0,)


def release_is_newer(latest: str, current: str) -> bool:
    return version_tuple(latest) > version_tuple(current)


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
    term.check_for_update(apply=False)
    while True:
        print("\nADMIN PLAN - FULL LAB AUTOMATION")
        print("1) Auto-run HXSecurity Test 1")
        print("2) Auto-run HXSecurity Test 2")
        print("3) Auto-run HXSecurity Test 3")
        print("4) Auto-run HXSecurity Test 4")
        print("5) Check/install terminal update")
        print("6) Show registered tests")
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
            url = input("Start URL/domain: ").strip() or "https://lab.hxsecurity.net/test4/login"
            ok = term.run_test4_auto(url)
            print("[result] PASS" if ok else "[result] FAIL")
        elif choice == "5":
            term.check_for_update(apply=True)
        elif choice == "6":
            print("Registered tests:")
            print("- test1: exposed backup/config artifact with Base64 credential, admin login validation")
            print("- test2: chained robots/header/manifest clue with Base64 credential, admin login validation")
            print("- test3: chained security/header/runbook/manifest clue with Base64 credential, admin login validation")
            print("- test4: chained sitemap/status/manifest archived-env clue with Base64 credential, admin login validation")
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
