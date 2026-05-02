# ============================================================
# QuantumGuard — Vulnerability Patterns v2.5
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# Standards: NIST FIPS 203, FIPS 204, FIPS 205
# ============================================================
#
# v2.5 changes vs v2.4:
#   FIX-1  ECC: removed x25519/curve25519 — these are NOT quantum-broken
#           in the same way (used in hybrid PQC, not classical ECDSA/ECDH).
#           Flagging them as CRITICAL was a factual error that would mislead users.
#   FIX-2  HARDCODED_SECRET: tightened regex to require non-trivial values.
#           Previous pattern matched "password = 'required'" in validation schemas.
#   FIX-3  WEAK_RANDOM: removed generic rand() and mt_rand() — these fire
#           constantly in non-crypto code (e.g. UI animations, test data).
#           Context gate in scan.py handles this already.
#   FIX-4  SHA256_SIGNED: removed RS256/ES256/PS256 — these are JWT algorithm
#           names that appear legitimately in config and docs. Too noisy.
#   FIX-5  Go/Rust/C patterns: removed overly broad patterns that match
#           variable names containing "key" (e.g. map keys, config keys).
#   FIX-6  Added SEVERITY_SCORE at bottom (required by scan.py import).
# ============================================================

VULNERABLE_PATTERNS = {

    # ── RSA ──────────────────────────────────────────────────
    "RSA": {
        "severity": "CRITICAL",
        "replacement": "CRYSTALS-Kyber (ML-KEM FIPS 203)",
        "patterns": [
            # Python — PyCryptodome
            r"RSA\.generate\s*\(",
            r"RSA\.import_key\s*\(",
            r"RSA\.export_key\s*\(",
            r"PKCS1_OAEP",
            r"PKCS1_v1_5",
            r"from\s+Crypto\.PublicKey\s+import\s+RSA",
            # Python — cryptography library
            r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa",
            r"rsa\.generate_private_key\s*\(",
            # JavaScript / Node.js
            r"generateKeyPairSync\s*\(\s*['\"]rsa['\"]",
            r"crypto\.publicEncrypt\s*\(",
            r"crypto\.privateDecrypt\s*\(",
            r"new\s+NodeRSA\s*\(",
            r"forge\.pki\.rsa\.",
            # Java
            r"KeyPairGenerator\.getInstance\s*\(\s*['\"]RSA['\"]",
            r"RSAPublicKeySpec",
            r"RSAPrivateKeySpec",
            # Go
            r"rsa\.GenerateKey\s*\(",
            r"rsa\.EncryptPKCS1v15\s*\(",
            r"rsa\.DecryptPKCS1v15\s*\(",
            r"rsa\.SignPKCS1v15\s*\(",
            # Rust
            r"RsaPrivateKey::new\s*\(",
            r"Pkcs1v15Encrypt",
            r"Pkcs1v15Sign",
            # Ruby
            r"OpenSSL::PKey::RSA\.new",
        ],
    },

    # ── ECC ──────────────────────────────────────────────────
    # FIX-1: Removed x25519 and curve25519.
    # x25519 is used in hybrid PQC (X25519+ML-KEM) and is NOT the same as
    # classical ECDSA/ECDH over NIST curves. Flagging it as CRITICAL is wrong.
    # ECDSA and ECDH over NIST curves (P-256, P-384, P-521, secp256k1) ARE vulnerable.
    "ECC": {
        "severity": "CRITICAL",
        "replacement": "CRYSTALS-Dilithium (ML-DSA FIPS 204)",
        "patterns": [
            # Python — cryptography library
            r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+ec\b",
            r"ec\.generate_private_key\s*\(",
            r"ec\.SECP256R1\b",
            r"ec\.SECP384R1\b",
            r"ec\.SECP521R1\b",
            r"ec\.SECP256K1\b",
            # Python — PyCryptodome
            r"from\s+Crypto\.PublicKey\s+import\s+ECC",
            r"ECC\.generate\s*\(",
            # JavaScript / Node.js
            r"createECDH\s*\(",
            r"generateKeyPairSync\s*\(\s*['\"]ec['\"]",
            r"elliptic\.ec\s*\(",
            r"secp256k1",
            r"prime256v1",
            r"brainpool",
            # Specific ECDSA/ECDH references
            r"\bECDSA\b",
            r"\bECDH\b",
            # Java
            r"KeyPairGenerator\.getInstance\s*\(\s*['\"]EC['\"]",
            r"ECPublicKeySpec",
            r"ECPrivateKeySpec",
            # Go
            r"elliptic\.P256\s*\(",
            r"elliptic\.P384\s*\(",
            r"elliptic\.P521\s*\(",
            r"ecdsa\.GenerateKey\s*\(",
            r"ecdsa\.Sign\s*\(",
            r"ecdsa\.Verify\s*\(",
            # Rust
            r"p256::SecretKey",
            r"p384::SecretKey",
            r"k256::SecretKey",
            r"ecdsa::SigningKey",
            # Ruby
            r"OpenSSL::PKey::EC\.new",
        ],
    },

    # ── Diffie-Hellman ───────────────────────────────────────
    "DH": {
        "severity": "HIGH",
        "replacement": "CRYSTALS-Kyber (ML-KEM FIPS 203)",
        "patterns": [
            r"\bDHE\b",
            r"DiffieHellman",
            r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+dh\b",
            r"dh\.generate_parameters\s*\(",
            r"getDiffieHellman\s*\(",
            r"createDiffieHellman\s*\(",
            r"KeyPairGenerator\.getInstance\s*\(\s*['\"]DH['\"]",
            r"DHPublicKeySpec",
            r"DHPrivateKeySpec",
            r"javax\.crypto\.interfaces\.DHKey",
        ],
    },

    # ── DSA ──────────────────────────────────────────────────
    "DSA": {
        "severity": "HIGH",
        "replacement": "CRYSTALS-Dilithium (ML-DSA FIPS 204)",
        "patterns": [
            r"from\s+Crypto\.PublicKey\s+import\s+DSA",
            r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+dsa\b",
            r"dsa\.generate_private_key\s*\(",
            r"DSAKey",
            r"\bDSS\.",
            r"KeyPairGenerator\.getInstance\s*\(\s*['\"]DSA['\"]",
            r"generateKeyPairSync\s*\(\s*['\"]dsa['\"]",
            r"java\.security\.interfaces\.DSAKey",
            r"dsa\.GenerateKey\s*\(",
            r"dsa\.Sign\s*\(",
        ],
    },

    # ── MD5 ──────────────────────────────────────────────────
    "MD5": {
        "severity": "MEDIUM",
        "replacement": "SHA-3-256 or BLAKE3",
        "patterns": [
            r"hashlib\.md5\s*\(",
            r"\bMD5\s*\(\s*\)",
            r"\bnew\s+MD5\s*\(",
            r"createHash\s*\(\s*['\"]md5['\"]",
            r"DigestUtils\.md5",
            r"MessageDigest\.getInstance\s*\(\s*['\"]MD5['\"]",
            r"Digest::MD5",
            r"\bmd5sum\b",
            r"\bmd5_hex\b",
            r"crypto\.createHash\s*\(\s*['\"]md5['\"]",
            r"OpenSSL::Digest::MD5",
            r"md5\.New\s*\(\s*\)",
            r"\bmd5\.Sum\s*\(",
            r"md5::compute\s*\(",
            r"\bMd5::new\s*\(",
        ],
    },

    # ── SHA-1 ─────────────────────────────────────────────────
    "SHA1": {
        "severity": "MEDIUM",
        "replacement": "SHA-3-256 or BLAKE3",
        "patterns": [
            r"hashlib\.sha1\s*\(",
            r"\bSHA1\s*\(\s*\)",
            r"\bnew\s+SHA1\s*\(",
            r"createHash\s*\(\s*['\"]sha1['\"]",
            r"DigestUtils\.sha1",
            r"MessageDigest\.getInstance\s*\(\s*['\"]SHA-1['\"]",
            r"Digest::SHA1",
            r"\bsha1sum\b",
            r"\bsha1_hex\b",
            r"crypto\.createHash\s*\(\s*['\"]sha1['\"]",
            r"OpenSSL::Digest::SHA1",
            r"sha1\.New\s*\(\s*\)",
            r"\bsha1\.Sum\s*\(",
            r"sha1::Sha1",
            r"\bSha1::new\s*\(",
        ],
    },

    # ── SHA-256 with asymmetric signing ───────────────────────
    # FIX-4: Removed RS256/ES256/PS256 — these JWT algorithm name strings
    # appear legitimately in config files and documentation. Too noisy.
    # Only flag OpenSSL/Java OID-style references which are actual code.
    "SHA256_SIGNED": {
        "severity": "MEDIUM",
        "replacement": "SHA-3-256 (SHA-2 is quantum-weakened for signatures)",
        "patterns": [
            r"sha256WithRSAEncryption",
            r"SHA256withRSA",
            r"SHA256withECDSA",
            r"SHA256withDSA",
        ],
    },

    # ── RC4 ──────────────────────────────────────────────────
    "RC4": {
        "severity": "CRITICAL",
        "replacement": "AES-256-GCM or ChaCha20-Poly1305",
        "patterns": [
            r"\bRC4\b",
            r"\bARC4\b",
            r"\barc4\b",
            r"Cipher\.getInstance\s*\(\s*['\"]RC4['\"]",
            r"from\s+Crypto\.Cipher\s+import\s+ARC4",
            r"crypto\.createCipheriv\s*\(\s*['\"]rc4['\"]",
            r"rc4\.NewCipher\s*\(",
            r"\bRc4::new\s*\(",
        ],
    },

    # ── DES / 3DES ───────────────────────────────────────────
    "DES": {
        "severity": "CRITICAL",
        "replacement": "AES-256-GCM or ChaCha20-Poly1305",
        "patterns": [
            r"\b3DES\b",
            r"\bTripleDES\b",
            r"\bDESede\b",
            r"from\s+Crypto\.Cipher\s+import\s+DES\b",
            r"DES3\.new\s*\(",
            r"DES\.new\s*\(",
            r"Cipher\.getInstance\s*\(\s*['\"]DES",
            r"crypto\.createCipheriv\s*\(\s*['\"]des",
            r"OpenSSL::Cipher::DES",
            r"des\.NewCipher\s*\(",
            r"des\.NewTripleDESCipher\s*\(",
            r"\bDes::new\s*\(",
            r"\bTdesEde3::new\s*\(",
        ],
    },

    # ── ECB mode ─────────────────────────────────────────────
    "ECB_MODE": {
        "severity": "HIGH",
        "replacement": "AES-256-GCM or ChaCha20-Poly1305",
        "patterns": [
            r"AES\.MODE_ECB",
            r"DES\.MODE_ECB",
            r"Cipher\.getInstance\s*\(\s*['\"][^'\"]+/ECB",
            r"mode\s*=\s*['\"]?ECB['\"]?",
            r"AES/ECB",
            r"createCipheriv\s*\(\s*['\"]aes-\d+-ecb['\"]",
        ],
    },

    # ── Weak TLS ─────────────────────────────────────────────
    "WEAK_TLS": {
        "severity": "HIGH",
        "replacement": "TLS 1.3 minimum",
        "patterns": [
            r"ssl\.PROTOCOL_SSLv2\b",
            r"ssl\.PROTOCOL_SSLv3\b",
            r"ssl\.PROTOCOL_TLSv1\b",
            r"ssl\.PROTOCOL_TLSv1_1\b",
            r"\bSSLv2\b",
            r"\bSSLv3\b",
            r"\bTLSv1\b(?!\.2|\.3)",
            r"\bTLSv1\.1\b",
            r"secureProtocol.*SSLv",
            r"minVersion.*TLSv1\b(?!\.2|\.3)",
            r"TLS_RSA_WITH",
            r"tls\.VersionTLS10\b",
            r"tls\.VersionTLS11\b",
            r"tls\.VersionSSL30\b",
            r"ProtocolVersion::SSLv3",
            r"ProtocolVersion::TLSv1_0",
            r"ProtocolVersion::TLSv1_1",
            r"SSL_OP_NO_TLSv1_2",
            r"rejectUnauthorized\s*:\s*false",
        ],
    },

    # ── Weak key size ─────────────────────────────────────────
    "WEAK_KEY_SIZE": {
        "severity": "HIGH",
        "replacement": "RSA-4096 minimum or migrate to PQC (ML-KEM FIPS 203)",
        "patterns": [
            r"RSA\.generate\s*\(\s*(?:512|1024|2048)\s*\)",
            r"generate_private_key\s*\([^)]*key_size\s*=\s*(?:512|1024|2048)\b",
            r"rsa\.GenerateKey\s*\([^,]+,\s*(?:512|1024|2048)\s*\)",
            r"RsaPrivateKey::new\s*\([^,]+,\s*(?:512|1024|2048)\s*\)",
        ],
    },

    # ── Hardcoded secrets ─────────────────────────────────────
    # FIX-2: Tightened to require non-trivial values.
    # Previous patterns matched error messages, docs, and placeholder strings.
    # Now requires: at least 12 chars, not common placeholder words,
    # and only in assignment context (=, :) not in strings/comments.
    "HARDCODED_SECRET": {
        "severity": "HIGH",
        "replacement": "Use environment variables or a secret manager (AWS Secrets Manager, HashiCorp Vault)",
        "patterns": [
            # Private key PEM blocks — always flag, these are unambiguous
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----",
            # AWS credentials — very specific, low false positive
            r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{20,}['\"]",
            # JWT secrets with sufficient length (avoid matching "secret": "required")
            r"(?i)(?:jwt_secret|jwt_key|app_secret|signing_key|SECRET_KEY)\s*=\s*['\"][^'\"]{16,}['\"]",
            # API keys with typical format (long alphanumeric)
            r"(?i)api_key\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]",
            # Private key variable with long value
            r"(?i)private_key\s*=\s*['\"][^'\"]{20,}['\"]",
        ],
    },

    # ── Weak random ───────────────────────────────────────────
    # FIX-3: Removed rand() and mt_rand() — these fire constantly in
    # non-crypto PHP/C code. The crypto-context gate in scan.py handles
    # the remaining cases. Kept only the most unambiguous ones.
    "WEAK_RANDOM": {
        "severity": "MEDIUM",
        "replacement": "secrets module (Python) or crypto.getRandomValues() (JS)",
        "patterns": [
            r"random\.random\s*\(\s*\)",
            r"random\.randint\s*\(",
            r"random\.choice\s*\(",
            r"random\.randrange\s*\(",
            r"Math\.random\s*\(\s*\)",
            r"\bnew\s+Random\s*\(\s*\)",
            r"java\.util\.Random\b",
            # Go — math/rand (not crypto/rand)
            r'"math/rand"',
            r"\brand\.Intn\s*\(",
            r"\brand\.Float",
            # Rust — non-crypto RNG
            r"rand::thread_rng\s*\(\s*\)",
            r"\bSmallRng\b",
        ],
    },

    # ── JWT none algorithm ────────────────────────────────────
    "JWT_NONE_ALG": {
        "severity": "CRITICAL",
        "replacement": "Use RS256 with verified signature; never use algorithm=none",
        "patterns": [
            r"algorithm\s*=\s*['\"]none['\"]",
            r"algorithms\s*=\s*\[['\"]none['\"]",
            r"verify\s*=\s*False",
            r"verify_signature.*False",
            r"options\s*=\s*\{[^}]*\"verify_signature\"\s*:\s*False",
        ],
    },

    # ── Blowfish ─────────────────────────────────────────────
    "BLOWFISH": {
        "severity": "HIGH",
        "replacement": "AES-256-GCM",
        "patterns": [
            r"\bBlowfish\b",
            r"\bblowfish\b",
            r"Cipher\.getInstance\s*\(\s*['\"]Blowfish['\"]",
            r"from\s+Crypto\.Cipher\s+import\s+Blowfish",
            r"golang\.org/x/crypto/blowfish",
            r"blowfish::Blowfish",
        ],
    },

    # ── MD4 ──────────────────────────────────────────────────
    "MD4": {
        "severity": "CRITICAL",
        "replacement": "SHA-3-256 or BLAKE3",
        "patterns": [
            r"\bMD4\b",
            r"\bmd4\b",
            r"MessageDigest\.getInstance\s*\(\s*['\"]MD4['\"]",
        ],
    },

    # ── Go-specific patterns ──────────────────────────────────
    # FIX-5: Removed overly broad patterns.
    "RSA_GO": {
        "patterns": [
            r"rsa\.GenerateKey\s*\(",
            r"rsa\.EncryptPKCS1v15\s*\(",
            r"rsa\.SignPKCS1v15\s*\(",
        ],
        "severity": "CRITICAL",
        "replacement": "golang.org/x/crypto — CRYSTALS-Kyber (ML-KEM FIPS 203)",
    },
    "ECC_GO": {
        "patterns": [
            r"elliptic\.P256\s*\(\s*\)",
            r"elliptic\.P384\s*\(\s*\)",
            r"ecdsa\.GenerateKey\s*\(",
        ],
        "severity": "CRITICAL",
        "replacement": "CRYSTALS-Dilithium (ML-DSA FIPS 204)",
    },
    "MD5_GO": {
        "patterns": [r"md5\.New\s*\(\s*\)", r"\bmd5\.Sum\s*\("],
        "severity": "MEDIUM",
        "replacement": "crypto/sha3 — SHA3-256",
    },
    "SHA1_GO": {
        "patterns": [r"sha1\.New\s*\(\s*\)", r"\bsha1\.Sum\s*\("],
        "severity": "MEDIUM",
        "replacement": "crypto/sha3 — SHA3-256",
    },
    "DES_GO": {
        "patterns": [r"des\.NewCipher\s*\(", r"des\.NewTripleDESCipher\s*\("],
        "severity": "CRITICAL",
        "replacement": "crypto/aes — AES-256-GCM",
    },
    "WEAK_TLS_GO": {
        "patterns": [
            r"tls\.VersionTLS10\b",
            r"tls\.VersionTLS11\b",
            r"InsecureSkipVerify\s*:\s*true",
        ],
        "severity": "HIGH",
        "replacement": "tls.VersionTLS13 minimum",
    },

    # ── Rust-specific patterns ────────────────────────────────
    "RSA_RUST": {
        "patterns": [
            r"RsaPrivateKey::new\s*\(",
            r"Pkcs1v15Encrypt",
        ],
        "severity": "CRITICAL",
        "replacement": "pqcrypto-kyber crate — CRYSTALS-Kyber (ML-KEM FIPS 203)",
    },
    "MD5_RUST": {
        "patterns": [r"md5::compute\s*\(", r"\bMd5::new\s*\("],
        "severity": "MEDIUM",
        "replacement": "sha3 crate — SHA3-256",
    },
    "SHA1_RUST": {
        "patterns": [r"sha1::Sha1", r"\bSha1::new\s*\("],
        "severity": "MEDIUM",
        "replacement": "sha3 crate — SHA3-256",
    },
    "WEAK_TLS_RUST": {
        "patterns": [
            r"danger_accept_invalid_certs\s*\(\s*true\s*\)",
        ],
        "severity": "HIGH",
        "replacement": "rustls with TLS 1.3 only",
    },
    "ECC_RUST": {
        "patterns": [
            r"p256::SecretKey",
            r"k256::SecretKey",
            r"ecdsa::SigningKey",
        ],
        "severity": "CRITICAL",
        "replacement": "pqcrypto-dilithium — CRYSTALS-Dilithium (ML-DSA FIPS 204)",
    },

    # ── C / C++ patterns ─────────────────────────────────────
    # FIX-5: Removed "unsigned char key[]" — matches any byte array named key.
    "RSA_C": {
        "patterns": [
            r"RSA_generate_key\s*\(",
            r"RSA_public_encrypt\s*\(",
            r"RSA_private_decrypt\s*\(",
            r"EVP_PKEY_RSA\b",
        ],
        "severity": "CRITICAL",
        "replacement": "liboqs — CRYSTALS-Kyber (ML-KEM FIPS 203)",
    },
    "ECC_C": {
        "patterns": [
            r"EC_KEY_new_by_curve_name\s*\(",
            r"ECDSA_sign\s*\(",
            r"ECDSA_verify\s*\(",
            r"EC_GROUP_new\s*\(",
        ],
        "severity": "CRITICAL",
        "replacement": "liboqs — CRYSTALS-Dilithium (ML-DSA FIPS 204)",
    },
    "MD5_C": {
        "patterns": [
            r"MD5_Init\s*\(",
            r"MD5_Update\s*\(",
            r"MD5_Final\s*\(",
            r"EVP_md5\s*\(\s*\)",
        ],
        "severity": "MEDIUM",
        "replacement": "SHA3_256 from OpenSSL 3.x",
    },
    "SHA1_C": {
        "patterns": [
            r"SHA1_Init\s*\(",
            r"SHA1_Update\s*\(",
            r"SHA1_Final\s*\(",
            r"EVP_sha1\s*\(\s*\)",
        ],
        "severity": "MEDIUM",
        "replacement": "EVP_sha3_256() from OpenSSL 3.x",
    },
    "DES_C": {
        "patterns": [
            r"DES_set_key\s*\(",
            r"DES_ecb_encrypt\s*\(",
            r"EVP_des_\w",
            r"EVP_des_ede3",
        ],
        "severity": "CRITICAL",
        "replacement": "EVP_aes_256_gcm() from OpenSSL",
    },
    "RC4_C": {
        "patterns": [
            r"RC4_set_key\s*\(",
            r"\bRC4\s*\(",
            r"EVP_rc4\s*\(\s*\)",
        ],
        "severity": "CRITICAL",
        "replacement": "EVP_aes_256_gcm() from OpenSSL",
    },
    "WEAK_SSL_C": {
        "patterns": [
            r"SSLv2_method\s*\(\s*\)",
            r"SSLv3_method\s*\(\s*\)",
            r"TLSv1_method\s*\(\s*\)",
            r"SSL_OP_NO_TLSv1_2\b",
        ],
        "severity": "HIGH",
        "replacement": "TLS_method() with TLS_MIN_VERSION = TLS1_3_VERSION",
    },
    "RAND_C": {
        "patterns": [
            r"\brand\s*\(\s*\)",
            r"\bsrand\s*\(",
        ],
        "severity": "MEDIUM",
        "replacement": "RAND_bytes() from OpenSSL for cryptographic randomness",
    },
}


# ── Severity scores for calculate_score() ────────────────────
SEVERITY_SCORE = {
    "CRITICAL": 10,
    "HIGH":     6,
    "MEDIUM":   3,
    "LOW":      1,
}
