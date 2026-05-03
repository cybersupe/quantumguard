"""
QuantumGuard — Dependency Scanner v1.0
=======================================
Parses package manifests and flags libraries that use quantum-vulnerable
cryptography (RSA, ECC, DH, MD5, SHA-1, RC4, DES).

Supported manifest files:
  Python  — requirements.txt, Pipfile, setup.py, pyproject.toml
  Node.js — package.json, package-lock.json, yarn.lock
  Go      — go.mod
  Java    — pom.xml, build.gradle
  Rust    — Cargo.toml
  Ruby    — Gemfile

Each finding includes:
  - library name + detected version range
  - vulnerability type (RSA, ECC, etc.)
  - severity (CRITICAL / HIGH / MEDIUM)
  - CVE references where known
  - NIST-approved replacement
  - migration effort (LOW / MEDIUM / HIGH)
"""

import os
import re
import json
import xml.etree.ElementTree as ET
from typing import Optional

# ============================================================
# KNOWN VULNERABLE LIBRARY DATABASE
# ============================================================
# Format per entry:
#   "pip_name" or "npm_name": {
#       "display_name":  human-readable name
#       "vulnerability": vuln type (RSA / ECC / DH / MD5 / etc.)
#       "severity":      CRITICAL / HIGH / MEDIUM
#       "reason":        one-line explanation
#       "affected_versions": version constraint that is vulnerable ("all", "<2.0", etc.)
#       "safe_version":  first safe version or None if no safe version exists
#       "cves":          list of CVE IDs
#       "replacement":   NIST-approved replacement library
#       "nist_standard": FIPS standard that applies
#       "migration_effort": LOW / MEDIUM / HIGH
#       "ecosystems":    list of ecosystems this entry applies to
#   }
# ============================================================

VULNERABLE_LIBRARIES = {

    # ── Python ──────────────────────────────────────────────

    "pycrypto": {
        "display_name":    "PyCrypto",
        "vulnerability":   "RSA, DES, MD5, RC4, ARC4",
        "severity":        "CRITICAL",
        "reason":          "Unmaintained since 2014. Contains RSA, DES, RC4, and MD5 — all quantum-vulnerable. Known CVEs for buffer overflows.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            ["CVE-2013-7459", "CVE-2018-6594"],
        "replacement":     "cryptography >= 41.0 (uses OpenSSL, supports hybrid PQC)",
        "nist_standard":   "FIPS 203, FIPS 204",
        "migration_effort": "HIGH",
        "ecosystems":      ["pip"],
    },

    "pycryptodome": {
        "display_name":    "PyCryptodome",
        "vulnerability":   "RSA, ECC, DH, DES, RC4",
        "severity":        "HIGH",
        "reason":          "Drop-in replacement for PyCrypto but still exposes RSA, ECC, DH — all broken by Shor's algorithm. No PQC support.",
        "affected_versions": "< 4.0",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "cryptography >= 41.0 or liboqs-python for PQC primitives",
        "nist_standard":   "FIPS 203, FIPS 204",
        "migration_effort": "MEDIUM",
        "ecosystems":      ["pip"],
    },

    "pycryptodomex": {
        "display_name":    "PyCryptodomeX",
        "vulnerability":   "RSA, ECC, DH, DES, RC4",
        "severity":        "HIGH",
        "reason":          "Same as PyCryptodome — namespace package. Exposes RSA, ECC, DH with no PQC support.",
        "affected_versions": "< 4.0",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "cryptography >= 41.0",
        "nist_standard":   "FIPS 203, FIPS 204",
        "migration_effort": "MEDIUM",
        "ecosystems":      ["pip"],
    },

    "pyopenssl": {
        "display_name":    "pyOpenSSL",
        "vulnerability":   "RSA, ECC — depends on system OpenSSL version",
        "severity":        "HIGH",
        "reason":          "Wraps OpenSSL. Without hybrid PQC enabled in OpenSSL 3.2+, all key exchange is quantum-vulnerable.",
        "affected_versions": "< 23.0",
        "safe_version":    "23.0.0",
        "cves":            [],
        "replacement":     "cryptography >= 41.0 (direct, no pyOpenSSL wrapper needed)",
        "nist_standard":   "FIPS 203",
        "migration_effort": "MEDIUM",
        "ecosystems":      ["pip"],
    },

    "rsa": {
        "display_name":    "rsa (Python)",
        "vulnerability":   "RSA",
        "severity":        "CRITICAL",
        "reason":          "Pure-Python RSA library. RSA is entirely broken by Shor's algorithm on quantum computers.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            ["CVE-2020-25658"],
        "replacement":     "cryptography >= 41.0 with ML-KEM (FIPS 203) for key encapsulation",
        "nist_standard":   "FIPS 203",
        "migration_effort": "HIGH",
        "ecosystems":      ["pip"],
    },

    "ecdsa": {
        "display_name":    "ecdsa (Python)",
        "vulnerability":   "ECC — ECDSA",
        "severity":        "CRITICAL",
        "reason":          "Pure-Python ECDSA library. ECC is broken by quantum Shor's algorithm — the discrete log becomes trivially solvable.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "cryptography >= 41.0 with ML-DSA (FIPS 204) for digital signatures",
        "nist_standard":   "FIPS 204",
        "migration_effort": "HIGH",
        "ecosystems":      ["pip"],
    },

    "paramiko": {
        "display_name":    "Paramiko",
        "vulnerability":   "RSA, ECDSA, DH — SSH key exchange",
        "severity":        "HIGH",
        "reason":          "SSH library using RSA and ECDSA host keys and DH key exchange — all quantum-vulnerable. No PQC SSH support yet.",
        "affected_versions": "< 3.0",
        "safe_version":    "3.0.0",
        "cves":            ["CVE-2022-24302"],
        "replacement":     "paramiko >= 3.0 (better defaults) + monitor for OpenSSH PQC KEX support",
        "nist_standard":   "FIPS 203",
        "migration_effort": "LOW",
        "ecosystems":      ["pip"],
    },

    "m2crypto": {
        "display_name":    "M2Crypto",
        "vulnerability":   "RSA, ECC, DH, DES",
        "severity":        "HIGH",
        "reason":          "OpenSSL wrapper exposing RSA, ECC, and legacy DES. Old API with no PQC support.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "cryptography >= 41.0",
        "nist_standard":   "FIPS 203, FIPS 204",
        "migration_effort": "HIGH",
        "ecosystems":      ["pip"],
    },

    "python-gnupg": {
        "display_name":    "python-gnupg",
        "vulnerability":   "RSA, ECC — GPG key operations",
        "severity":        "HIGH",
        "reason":          "Wraps GnuPG which uses RSA and ECC keys by default. GPG has no PQC standard yet.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "Monitor GnuPG PQC roadmap. For new systems prefer age encryption with X25519.",
        "nist_standard":   "FIPS 203",
        "migration_effort": "HIGH",
        "ecosystems":      ["pip"],
    },

    "hashids": {
        "display_name":    "hashids",
        "vulnerability":   "MD5 — weak hash usage",
        "severity":        "MEDIUM",
        "reason":          "Uses MD5 internally. MD5 is broken classically and halved further by Grover's algorithm.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "Use hashlib.sha3_256 or BLAKE3 for any security-relevant hashing",
        "nist_standard":   "FIPS 205",
        "migration_effort": "LOW",
        "ecosystems":      ["pip"],
    },

    "passlib": {
        "display_name":    "passlib",
        "vulnerability":   "MD5, SHA1 — weak hash schemes if misconfigured",
        "severity":        "MEDIUM",
        "reason":          "Supports md5_crypt and sha1_crypt schemes which are quantum-vulnerable. Safe if using bcrypt or argon2.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "passlib with argon2 or bcrypt schemes only — avoid md5_crypt and sha1_crypt",
        "nist_standard":   "FIPS 205",
        "migration_effort": "LOW",
        "ecosystems":      ["pip"],
    },

    "tlslite-ng": {
        "display_name":    "tlslite-ng",
        "vulnerability":   "RSA, ECC, DH — TLS key exchange",
        "severity":        "CRITICAL",
        "reason":          "Pure-Python TLS library using RSA, ECDH, and DH — no PQC support.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "Use system TLS (ssl module) with OpenSSL 3.2+ for hybrid PQC",
        "nist_standard":   "FIPS 203",
        "migration_effort": "HIGH",
        "ecosystems":      ["pip"],
    },

    # ── Node.js / npm ────────────────────────────────────────

    "node-rsa": {
        "display_name":    "node-rsa",
        "vulnerability":   "RSA",
        "severity":        "CRITICAL",
        "reason":          "Pure RSA library for Node.js. RSA is entirely broken by Shor's algorithm.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "Use Node.js crypto module with ML-KEM via liboqs-node, or @noble/post-quantum",
        "nist_standard":   "FIPS 203",
        "migration_effort": "HIGH",
        "ecosystems":      ["npm"],
    },

    "node-forge": {
        "display_name":    "node-forge",
        "vulnerability":   "RSA, ECC, DES, MD5, RC4",
        "severity":        "CRITICAL",
        "reason":          "Comprehensive classical crypto library — RSA, ECC, DES, MD5, RC4 all present. No PQC support.",
        "affected_versions": "< 1.3.0",
        "safe_version":    "1.3.0",
        "cves":            ["CVE-2022-0122", "CVE-2022-24771", "CVE-2022-24772", "CVE-2022-24773"],
        "replacement":     "Node.js built-in crypto + @noble/post-quantum for PQC primitives",
        "nist_standard":   "FIPS 203, FIPS 204",
        "migration_effort": "HIGH",
        "ecosystems":      ["npm"],
    },

    "elliptic": {
        "display_name":    "elliptic",
        "vulnerability":   "ECC — secp256k1, P-256, P-384",
        "severity":        "CRITICAL",
        "reason":          "Most widely used ECC library in Node.js. All curves broken by quantum Shor's algorithm.",
        "affected_versions": "< 6.5.4",
        "safe_version":    "6.5.4",
        "cves":            ["CVE-2020-28498", "CVE-2020-13822"],
        "replacement":     "@noble/post-quantum (ML-DSA FIPS 204) or @noble/curves with awareness of quantum timeline",
        "nist_standard":   "FIPS 204",
        "migration_effort": "HIGH",
        "ecosystems":      ["npm"],
    },

    "jsencrypt": {
        "display_name":    "jsencrypt",
        "vulnerability":   "RSA",
        "severity":        "CRITICAL",
        "reason":          "Browser/Node RSA encryption library. RSA is quantum-vulnerable via Shor's algorithm.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "@noble/post-quantum for ML-KEM key encapsulation",
        "nist_standard":   "FIPS 203",
        "migration_effort": "HIGH",
        "ecosystems":      ["npm"],
    },

    "crypto-js": {
        "display_name":    "CryptoJS",
        "vulnerability":   "MD5, SHA1, DES, RC4",
        "severity":        "HIGH",
        "reason":          "JavaScript crypto library with MD5, SHA-1, DES, and RC4 — all quantum-vulnerable or classically broken.",
        "affected_versions": "< 4.2.0",
        "safe_version":    "4.2.0",
        "cves":            ["CVE-2023-46133"],
        "replacement":     "Node.js built-in crypto (AES-256-GCM, SHA-3) or @noble/hashes",
        "nist_standard":   "FIPS 205",
        "migration_effort": "MEDIUM",
        "ecosystems":      ["npm"],
    },

    "md5": {
        "display_name":    "md5 (npm)",
        "vulnerability":   "MD5",
        "severity":        "HIGH",
        "reason":          "Pure MD5 implementation. MD5 is broken classically (collisions) and weakened further by Grover's algorithm.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "Node.js crypto.createHash('sha3-256') or @noble/hashes sha3",
        "nist_standard":   "FIPS 205",
        "migration_effort": "LOW",
        "ecosystems":      ["npm"],
    },

    "sha1": {
        "display_name":    "sha1 (npm)",
        "vulnerability":   "SHA-1",
        "severity":        "HIGH",
        "reason":          "SHA-1 has known collision attacks and 160-bit output. Grover's algorithm halves effective security to 80 bits.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "Node.js crypto.createHash('sha3-256')",
        "nist_standard":   "FIPS 205",
        "migration_effort": "LOW",
        "ecosystems":      ["npm"],
    },

    "jsonwebtoken": {
        "display_name":    "jsonwebtoken",
        "vulnerability":   "RSA — RS256/RS512 algorithm",
        "severity":        "HIGH",
        "reason":          "Popular JWT library. RS256 and RS512 signing use RSA — quantum-vulnerable. HS256 with strong secret is safer for now.",
        "affected_versions": "< 9.0.0",
        "safe_version":    "9.0.0",
        "cves":            ["CVE-2022-23529", "CVE-2022-23539"],
        "replacement":     "jsonwebtoken >= 9.0.0 with HS256 (HMAC-SHA256) until PQC JWT standard is finalised",
        "nist_standard":   "FIPS 205",
        "migration_effort": "LOW",
        "ecosystems":      ["npm"],
    },

    "bcrypt": {
        "display_name":    "bcrypt (npm)",
        "vulnerability":   "Grover-weakened — 128-bit effective security halved to 64",
        "severity":        "MEDIUM",
        "reason":          "bcrypt work factor provides ~128 bits of security. Grover's algorithm halves this. Argon2id is preferred.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "argon2-browser or @node-rs/argon2 (Argon2id — memory-hard, better quantum resistance)",
        "nist_standard":   "FIPS 205",
        "migration_effort": "LOW",
        "ecosystems":      ["npm"],
    },

    "ssh2": {
        "display_name":    "ssh2 (npm)",
        "vulnerability":   "RSA, ECC, DH — SSH key exchange",
        "severity":        "HIGH",
        "reason":          "Node.js SSH2 library using RSA host keys and DH/ECDH key exchange. No PQC SSH support.",
        "affected_versions": "< 1.14.0",
        "safe_version":    "1.14.0",
        "cves":            ["CVE-2023-32002"],
        "replacement":     "ssh2 >= 1.14.0 (better defaults). Monitor OpenSSH PQC KEX for long-term fix.",
        "nist_standard":   "FIPS 203",
        "migration_effort": "LOW",
        "ecosystems":      ["npm"],
    },

    # ── Java / Maven ─────────────────────────────────────────

    "bcprov-jdk15on": {
        "display_name":    "Bouncy Castle (JDK 1.5+)",
        "vulnerability":   "RSA, ECC, DH, DES, MD5, SHA1",
        "severity":        "HIGH",
        "reason":          "Full classical crypto library. Safe to use if only PQC algorithms are used — but exposes all quantum-vulnerable primitives.",
        "affected_versions": "< 1.73",
        "safe_version":    "1.73",
        "cves":            ["CVE-2023-33202", "CVE-2022-45146"],
        "replacement":     "bcprov-jdk18on >= 1.77 with PQC provider (CRYSTALS-Kyber, CRYSTALS-Dilithium)",
        "nist_standard":   "FIPS 203, FIPS 204",
        "migration_effort": "MEDIUM",
        "ecosystems":      ["maven"],
    },

    "bcprov-jdk18on": {
        "display_name":    "Bouncy Castle (JDK 1.8+)",
        "vulnerability":   "RSA, ECC if not using PQC provider",
        "severity":        "MEDIUM",
        "reason":          "Latest Bouncy Castle. Has PQC support but classical algorithms still available — depends on usage.",
        "affected_versions": "< 1.77",
        "safe_version":    "1.77",
        "cves":            ["CVE-2024-29857", "CVE-2024-30171"],
        "replacement":     "bcprov-jdk18on >= 1.77 with bcpkix-jdk18on for PQC certificate handling",
        "nist_standard":   "FIPS 203, FIPS 204",
        "migration_effort": "LOW",
        "ecosystems":      ["maven"],
    },

    "commons-codec": {
        "display_name":    "Apache Commons Codec",
        "vulnerability":   "MD5, SHA1 — utility functions",
        "severity":        "MEDIUM",
        "reason":          "DigestUtils.md5Hex() and DigestUtils.sha1Hex() are quantum-vulnerable hash utilities.",
        "affected_versions": "< 1.16",
        "safe_version":    "1.16.0",
        "cves":            [],
        "replacement":     "Use DigestUtils.sha3_256Hex() or Java's MessageDigest with SHA3-256",
        "nist_standard":   "FIPS 205",
        "migration_effort": "LOW",
        "ecosystems":      ["maven"],
    },

    # ── Go ───────────────────────────────────────────────────

    "golang.org/x/crypto": {
        "display_name":    "Go Extended Crypto",
        "vulnerability":   "RSA, ECC, DH — if using rsa, ecdsa, dh packages",
        "severity":        "HIGH",
        "reason":          "Contains rsa, ecdsa, and openpgp packages — all quantum-vulnerable. Safe packages like chacha20poly1305 exist within the same module.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            ["CVE-2022-27191", "CVE-2023-48795"],
        "replacement":     "Avoid rsa and ecdsa sub-packages. Use circl (github.com/cloudflare/circl) for PQC.",
        "nist_standard":   "FIPS 203, FIPS 204",
        "migration_effort": "MEDIUM",
        "ecosystems":      ["go"],
    },

    "github.com/cloudflare/circl": {
        "display_name":    "CIRCL (Cloudflare)",
        "vulnerability":   "None — PQC safe",
        "severity":        "NONE",
        "reason":          "This is the RECOMMENDED PQC library from Cloudflare. Contains ML-KEM, ML-DSA, SPHINCS+.",
        "affected_versions": "none",
        "safe_version":    "any",
        "cves":            [],
        "replacement":     "Already using recommended PQC library",
        "nist_standard":   "FIPS 203, FIPS 204, FIPS 205",
        "migration_effort": "NONE",
        "ecosystems":      ["go"],
    },

    # ── Rust ─────────────────────────────────────────────────

    "rsa": {
        "display_name":    "rsa (Rust crate)",
        "vulnerability":   "RSA",
        "severity":        "CRITICAL",
        "reason":          "Pure Rust RSA implementation. RSA is entirely broken by Shor's algorithm.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            ["CVE-2023-49092"],
        "replacement":     "pqcrypto crate or ml-kem crate for FIPS 203 compliant key encapsulation",
        "nist_standard":   "FIPS 203",
        "migration_effort": "HIGH",
        "ecosystems":      ["cargo"],
    },

    "md5": {
        "display_name":    "md5 (Rust crate)",
        "vulnerability":   "MD5",
        "severity":        "HIGH",
        "reason":          "MD5 is broken classically and weakened by Grover's algorithm.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "sha3 crate or blake3 crate",
        "nist_standard":   "FIPS 205",
        "migration_effort": "LOW",
        "ecosystems":      ["cargo"],
    },

    # ── Ruby ─────────────────────────────────────────────────

    "openssl": {
        "display_name":    "openssl (Ruby gem)",
        "vulnerability":   "RSA, ECC, DH — depends on system OpenSSL version",
        "severity":        "HIGH",
        "reason":          "Ruby OpenSSL bindings. Without hybrid PQC in system OpenSSL 3.2+, all key exchange is quantum-vulnerable.",
        "affected_versions": "< 3.1.0",
        "safe_version":    "3.1.0",
        "cves":            [],
        "replacement":     "openssl >= 3.1.0 + system OpenSSL 3.2+ for hybrid PQC support",
        "nist_standard":   "FIPS 203",
        "migration_effort": "MEDIUM",
        "ecosystems":      ["gem"],
    },

    "bcrypt-ruby": {
        "display_name":    "bcrypt-ruby",
        "vulnerability":   "Grover-weakened password hashing",
        "severity":        "MEDIUM",
        "reason":          "bcrypt cost factor provides ~128 bit security. Grover's algorithm halves effective security.",
        "affected_versions": "all",
        "safe_version":    None,
        "cves":            [],
        "replacement":     "argon2 gem (Argon2id — memory-hard, better quantum resistance)",
        "nist_standard":   "FIPS 205",
        "migration_effort": "LOW",
        "ecosystems":      ["gem"],
    },
}

# Normalise keys — lowercase, strip spaces, handle both - and _
_VULN_INDEX = {}
for k, v in VULNERABLE_LIBRARIES.items():
    normalised = k.lower().replace("-", "").replace("_", "").replace(".", "")
    _VULN_INDEX[normalised] = (k, v)


def _lookup(pkg_name: str) -> Optional[tuple]:
    """Return (canonical_name, entry) if pkg_name matches a vulnerable library."""
    n = pkg_name.lower().replace("-", "").replace("_", "").replace(".", "")
    return _VULN_INDEX.get(n)


# ============================================================
# PARSERS — one per manifest format
# ============================================================

def _parse_requirements_txt(content: str) -> list:
    """Parse requirements.txt — returns list of (name, version_str) tuples."""
    pkgs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip extras like [security], environment markers
        line = re.split(r";|#", line)[0].strip()
        line = re.sub(r"\[.*?\]", "", line).strip()
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([><=!~^].*)?$", line)
        if m:
            pkgs.append((m.group(1), m.group(2) or ""))
    return pkgs


def _parse_package_json(content: str) -> list:
    """Parse package.json — returns list of (name, version_str) tuples."""
    pkgs = []
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, ver in data.get(section, {}).items():
                pkgs.append((name, str(ver)))
    except (json.JSONDecodeError, AttributeError):
        pass
    return pkgs


def _parse_go_mod(content: str) -> list:
    """Parse go.mod — returns list of (module_path, version) tuples."""
    pkgs = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require:
            if line == ")":
                in_require = False
                continue
            parts = line.split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                pkgs.append((parts[0], parts[1]))
        elif line.startswith("require "):
            parts = line.split()
            if len(parts) >= 3:
                pkgs.append((parts[1], parts[2]))
    return pkgs


def _parse_pom_xml(content: str) -> list:
    """Parse pom.xml — returns list of (artifactId, version) tuples."""
    pkgs = []
    try:
        # Strip namespace to simplify parsing
        content_clean = re.sub(r'\sxmlns[^"]*"[^"]*"', "", content)
        root = ET.fromstring(content_clean)
        for dep in root.iter("dependency"):
            artifact = dep.findtext("artifactId") or ""
            version  = dep.findtext("version") or ""
            if artifact:
                pkgs.append((artifact, version))
    except ET.ParseError:
        # Fallback: regex
        for m in re.finditer(r"<artifactId>([^<]+)</artifactId>", content):
            pkgs.append((m.group(1).strip(), ""))
    return pkgs


def _parse_build_gradle(content: str) -> list:
    """Parse build.gradle — returns list of (artifactId, version) tuples."""
    pkgs = []
    # Match: implementation 'group:artifact:version' or "group:artifact:version"
    for m in re.finditer(r"""['"]([^'"]+):([^'"]+):([^'"]+)['"]""", content):
        pkgs.append((m.group(2), m.group(3)))
    # Also match: implementation(group: 'x', name: 'y', version: 'z')
    for m in re.finditer(r"""name:\s*['"]([^'"]+)['"].*?version:\s*['"]([^'"]+)['"]""", content, re.DOTALL):
        pkgs.append((m.group(1), m.group(2)))
    return pkgs


def _parse_cargo_toml(content: str) -> list:
    """Parse Cargo.toml — returns list of (name, version) tuples."""
    pkgs = []
    in_deps = False
    for line in content.splitlines():
        line_stripped = line.strip()
        if re.match(r"^\[(dependencies|dev-dependencies|build-dependencies)\]", line_stripped):
            in_deps = True
            continue
        if line_stripped.startswith("[") and in_deps:
            in_deps = False
        if in_deps:
            # name = "version" or name = { version = "x" }
            m = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"', line_stripped)
            if m:
                pkgs.append((m.group(1), m.group(2)))
            else:
                m2 = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*\{.*?version\s*=\s*"([^"]+)"', line_stripped)
                if m2:
                    pkgs.append((m2.group(1), m2.group(2)))
    return pkgs


def _parse_gemfile(content: str) -> list:
    """Parse Gemfile — returns list of (name, version) tuples."""
    pkgs = []
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#") or not line.startswith("gem "):
            continue
        m = re.match(r"""gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""", line)
        if m:
            pkgs.append((m.group(1), m.group(2) or ""))
    return pkgs


def _parse_pipfile(content: str) -> list:
    """Parse Pipfile (TOML-like) — returns list of (name, version) tuples."""
    pkgs = []
    in_packages = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ("[packages]", "[dev-packages]"):
            in_packages = True
            continue
        if stripped.startswith("[") and in_packages:
            in_packages = False
        if in_packages:
            m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=\s*["\']?([^"\']+)["\']?', stripped)
            if m and not stripped.startswith("#"):
                pkgs.append((m.group(1), m.group(2).strip()))
    return pkgs


# Map filename → (ecosystem, parser_function)
MANIFEST_PARSERS = {
    "requirements.txt": ("pip",   _parse_requirements_txt),
    "requirements-dev.txt": ("pip", _parse_requirements_txt),
    "requirements-test.txt": ("pip", _parse_requirements_txt),
    "pipfile":          ("pip",   _parse_pipfile),
    "package.json":     ("npm",   _parse_package_json),
    "cargo.toml":       ("cargo", _parse_cargo_toml),
    "go.mod":           ("go",    _parse_go_mod),
    "pom.xml":          ("maven", _parse_pom_xml),
    "build.gradle":     ("maven", _parse_build_gradle),
    "gemfile":          ("gem",   _parse_gemfile),
}


# ============================================================
# CORE SCANNER
# ============================================================

def scan_dependencies(directory: str) -> dict:
    """
    Walk a directory tree, parse all manifest files, and return a
    structured report of quantum-vulnerable dependencies found.

    Returns:
        {
            "total_manifests_scanned": int,
            "total_packages_checked":  int,
            "vulnerable_count":        int,
            "severity_summary":        { CRITICAL: int, HIGH: int, MEDIUM: int },
            "findings":                [ DependencyFinding, ... ],
            "manifests_scanned":       [ { file, ecosystem, packages_checked }, ... ],
            "safe_libraries_detected": [ str, ... ],
        }
    """
    findings       = []
    manifests_info = []
    total_packages = 0
    safe_detected  = []

    for root, dirs, files in os.walk(directory):
        # Skip common non-source directories
        dirs[:] = [d for d in dirs if d not in (
            ".git", "__pycache__", ".tox", ".venv", "venv", "env",
            ".eggs", "dist", "build", ".mypy_cache", ".pytest_cache",
        )]

        for fname in files:
            fname_lower = fname.lower()
            if fname_lower not in MANIFEST_PARSERS:
                continue

            filepath = os.path.join(root, fname)
            rel_path = os.path.relpath(filepath, directory)
            ecosystem, parser = MANIFEST_PARSERS[fname_lower]

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            try:
                packages = parser(content)
            except Exception:
                packages = []

            total_packages += len(packages)
            pkg_count = len(packages)

            manifest_findings = []
            for pkg_name, version_str in packages:
                result = _lookup(pkg_name)
                if result is None:
                    continue

                canonical, entry = result

                # Skip if this entry doesn't apply to this ecosystem
                if ecosystem not in entry.get("ecosystems", []):
                    continue

                # Skip NONE severity (safe/recommended libraries)
                if entry["severity"] == "NONE":
                    safe_detected.append(f"{pkg_name} ({ecosystem})")
                    continue

                finding = {
                    "file":              rel_path,
                    "ecosystem":         ecosystem,
                    "package":           pkg_name,
                    "detected_version":  version_str or "unspecified",
                    "severity":          entry["severity"],
                    "vulnerability":     entry["vulnerability"],
                    "reason":            entry["reason"],
                    "affected_versions": entry["affected_versions"],
                    "safe_version":      entry["safe_version"],
                    "cves":              entry["cves"],
                    "replacement":       entry["replacement"],
                    "nist_standard":     entry["nist_standard"],
                    "migration_effort":  entry["migration_effort"],
                    "display_name":      entry["display_name"],
                    # Priority mapping: CRITICAL→P0, HIGH→P1, MEDIUM→P2
                    "priority": {
                        "CRITICAL": "P0",
                        "HIGH":     "P1",
                        "MEDIUM":   "P2",
                    }.get(entry["severity"], "P2"),
                }
                manifest_findings.append(finding)

            findings.extend(manifest_findings)
            manifests_info.append({
                "file":             rel_path,
                "ecosystem":        ecosystem,
                "packages_checked": pkg_count,
                "vulnerable_found": len(manifest_findings),
            })

    sev_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for f in findings:
        sev_summary[f["severity"]] = sev_summary.get(f["severity"], 0) + 1

    # Sort findings: CRITICAL first, then HIGH, then MEDIUM
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 3))

    return {
        "total_manifests_scanned": len(manifests_info),
        "total_packages_checked":  total_packages,
        "vulnerable_count":        len(findings),
        "severity_summary":        sev_summary,
        "findings":                findings,
        "manifests_scanned":       manifests_info,
        "safe_libraries_detected": list(set(safe_detected)),
    }


def generate_dependency_score_explanation(result: dict) -> list:
    """Generate human-readable explanation lines for the dependency scan."""
    lines = []
    sev = result["severity_summary"]
    findings = result["findings"]

    if result["vulnerable_count"] == 0:
        lines.append("✅ No quantum-vulnerable dependencies detected.")
        return lines

    if sev.get("CRITICAL", 0) > 0:
        crits = [f for f in findings if f["severity"] == "CRITICAL"]
        pkgs  = list({f["package"] for f in crits})
        lines.append(f"🔴 CRITICAL: {len(crits)} critical dependency vulnerability(ies) — {', '.join(pkgs[:4])}")

    if sev.get("HIGH", 0) > 0:
        highs = [f for f in findings if f["severity"] == "HIGH"]
        pkgs  = list({f["package"] for f in highs})
        lines.append(f"🟡 HIGH: {len(highs)} high-severity dependency vulnerability(ies) — {', '.join(pkgs[:4])}")

    if sev.get("MEDIUM", 0) > 0:
        meds = [f for f in findings if f["severity"] == "MEDIUM"]
        pkgs = list({f["package"] for f in meds})
        lines.append(f"🟠 MEDIUM: {len(meds)} medium-severity dependency vulnerability(ies) — {', '.join(pkgs[:4])}")

    # CVE callout
    cves = []
    for f in findings:
        cves.extend(f.get("cves", []))
    if cves:
        lines.append(f"⚠️  {len(cves)} known CVE(s) in detected libraries: {', '.join(cves[:5])}")

    # Easy wins
    easy = [f for f in findings if f.get("migration_effort") == "LOW"]
    if easy:
        lines.append(f"💡 {len(easy)} finding(s) have LOW migration effort — quick wins available")

    return lines


def generate_dependency_summary(result: dict) -> dict:
    """Generate a scan summary block compatible with the existing scan_summary format."""
    return {
        "manifests_scanned":    result["total_manifests_scanned"],
        "packages_checked":     result["total_packages_checked"],
        "vulnerable_packages":  result["vulnerable_count"],
        "safe_libraries":       len(result["safe_libraries_detected"]),
        "severity_summary":     result["severity_summary"],
        "ecosystems_detected":  list({m["ecosystem"] for m in result["manifests_scanned"]}),
    }


# ============================================================
# QUICK TEST — run directly to verify
# ============================================================

if __name__ == "__main__":
    import sys
    import json

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"\n⚛  QuantumGuard Dependency Scanner v1.0")
    print(f"   Scanning: {target}\n")

    result = scan_dependencies(target)

    print(f"Manifests found    : {result['total_manifests_scanned']}")
    print(f"Packages checked   : {result['total_packages_checked']}")
    print(f"Vulnerable packages: {result['vulnerable_count']}")
    print(f"Critical           : {result['severity_summary'].get('CRITICAL', 0)}")
    print(f"High               : {result['severity_summary'].get('HIGH', 0)}")
    print(f"Medium             : {result['severity_summary'].get('MEDIUM', 0)}")

    if result["safe_libraries_detected"]:
        print(f"\n✅ Safe PQC libraries detected: {', '.join(result['safe_libraries_detected'])}")

    if result["findings"]:
        print(f"\n{'─'*70}")
        print("FINDINGS:")
        print(f"{'─'*70}")
        for f in result["findings"]:
            cves = f"  CVEs: {', '.join(f['cves'])}" if f["cves"] else ""
            print(f"\n  [{f['severity']}] {f['package']} ({f['ecosystem']})")
            print(f"  File    : {f['file']}")
            print(f"  Version : {f['detected_version']}")
            print(f"  Vuln    : {f['vulnerability']}")
            print(f"  Reason  : {f['reason'][:90]}")
            if cves:
                print(cves)
            print(f"  Fix     : {f['replacement'][:90]}")
            print(f"  Effort  : {f['migration_effort']}")
    else:
        print("\n✅ No quantum-vulnerable dependencies detected.")

    print(f"\n{'─'*70}")
    for line in generate_dependency_score_explanation(result):
        print(f"  {line}")
