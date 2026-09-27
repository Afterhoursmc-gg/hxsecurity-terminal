# HXSecurity Terminal

A consent-first local Python terminal for controlled H0RII/HXSecurity CTF labs.

It is designed for owned/authorized training targets only. It is not a general internet scanner.

## Plans

### ADMIN PLAN

Full lab automation for registered HXSecurity tests.

Enter the issued admin access code when prompted. The public `.py` validates admin access server-side, so the access code/hash is not stored in GitHub.

Optional self-hosted/operator override:

```bash
export HXSECURITY_ADMIN_KEY_SHA256="<sha256-of-your-admin-key>"
python3 hxsecurity_terminal.py
```

### PREMIUM PLAN — $9.99/month

Guided/manual mode.

Locked unless a premium key hash is issued:

```bash
export HXSECURITY_PREMIUM_KEY_SHA256="<sha256-of-premium-key>"
python3 hxsecurity_terminal.py
```

No premium access keys are included in this repository.

## Current registered tests

### Test 1

Automates the same authorized flow used in HXSecurity Test 1:

1. Ask for a lab URL/domain.
2. Enumerate realistic backup/config filenames.
3. Use a normal User-Agent so Cloudflare does not block the lab workflow.
4. Detect a Base64 credential marker.
5. Decode locally.
6. Login as `admin`.
7. Confirm the success banner.

### Test 2

Automates HXSecurity Test 2:

1. Ask for a lab URL/domain.
2. Trace a chained web-enumeration clue path.
3. Use login headers, robots metadata and a release manifest.
4. Recover a Base64 credential marker from the final lab artifact.
5. Decode locally.
6. Login as `admin`.
7. Confirm the Test 2 success banner.

### Test 3

Automates HXSecurity Test 3:

1. Ask for a lab URL/domain.
2. Trace a security-policy/header/runbook/manifest clue path.
3. Recover a Base64 credential marker from the final lab artifact.
4. Decode locally.
5. Login as `admin`.
6. Confirm the Test 3 success banner.

### Test 4

Automates HXSecurity Test 4:

1. Ask for a lab URL/domain.
2. Trace a sitemap/status/manifest archived-env clue path.
3. Recover a Base64 credential marker from the final lab artifact.
4. Decode locally.
5. Login as `admin`.
6. Confirm the Test 4 success banner.

### Test 5

Automates HXSecurity Test 5:

1. Ask for a lab URL/domain.
2. Trace a public app JS/source-map clue.
3. Enumerate a bounded object ID range.
4. Recover an unauthorized admin object and validation token.
5. Validate the BOLA/IDOR success condition.

## Auto-update

From v0.4.0 onward, Admin mode checks GitHub Releases for the latest `hxsecurity_terminal.py`. From v0.5.0 onward, Admin mode can also enable HXSecurity Protector live alerts and handles observe-mode soft 403/429 with bounded retries. Use menu option `5) Check/install terminal update` to replace the current script safely. A backup of the previous file is kept next to the script.

## Run

```bash
python3 hxsecurity_terminal.py
```

## Safety scope

Allowed target allowlist is restricted in code to:

- `hxsecurity.net`
- `*.hxsecurity.net`
- `*.horii.dev`
- localhost

Do not use this tool against third-party systems.

## Creating a key hash

```bash
python3 - <<'PY'
import hashlib, getpass
print(hashlib.sha256(getpass.getpass('key: ').encode()).hexdigest())
PY
```

Then export the resulting hash as one of the environment variables above.
