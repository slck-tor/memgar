# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | ✅ Active  |
| < 0.5   | ❌ No longer maintained |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing **security@memgar.io** with:

1. A description of the vulnerability and its potential impact
2. Steps to reproduce (proof-of-concept code is helpful)
3. Any suggested mitigations you've identified

We will acknowledge your report within **48 hours** and aim to provide a fix or mitigation within **14 days** for critical issues.

## Scope

In-scope vulnerabilities include:

- Bypass of threat detection (false-negative evasion techniques that evade all 4 layers)
- Pickle RCE via `_RestrictedUnpickler` allowlist bypass
- SSRF via `FeedLoader` (`_ALLOWED_HOSTS` bypass)
- Path traversal via `MEMGAR_CACHE_DIR`
- Feed signature forgery (Ed25519 bypass)
- Gzip bomb bypass (decompression limits)

Out of scope: issues in third-party dependencies (report those upstream), rate limiting bypasses, and low-severity informational findings.

## Disclosure Policy

We follow coordinated disclosure. Once a fix is released, we will:

1. Publish a CVE (if applicable)
2. Credit the reporter in the release notes (unless anonymity is requested)
3. Update `CHANGELOG.md` with a security advisory entry

## Bug Bounty

We do not currently operate a paid bug bounty program, but we recognize responsible reporters in our release notes and CONTRIBUTORS file.
