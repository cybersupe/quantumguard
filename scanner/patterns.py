VULNERABLE_PATTERNS = {
    "RSA": {
        "severity": "CRITICAL",
        "replacement": "CRYSTALS-Kyber (ML-KEM FIPS 203)",
        "patterns": [
            r"RSA\.generate", r"RSA\.import_key", r"RSA\.export_key",
            r"PKCS1_OAEP", r"PKCS1_v1_5",
            r"from Crypto\.PublicKey import RSA",
            r"from cryptography\.hazmat\.primitives\.asymmetric import rsa",
            r"rsa\.generate_private_key",
            r"rsa\.RSAPublicKey", r"rsa\.RSAPrivateKey",
            r"generateKeyPairSync\s*\(\s*['\"]rsa['\"]",
            r"KeyPairGenerator\.getInstance\s*\(\s*['\"]RSA['\"]",
            r"RSAPublicKeySpec", r"RSAPrivateKeySpec",
            r"forge\.pki\.rsa", r"new NodeRSA",
            r"crypto\.publicEncrypt", r"crypto\.privateDecrypt",
            r"OpenSSL::PKey::RSA",
            # Go
            r"rsa\.GenerateKey", r"rsa\.EncryptPKCS1v15",
            r"rsa\.DecryptPKCS1v15", r"rsa\.SignPKCS1v15",
            # Rust
            r"RsaPrivateKey::new", r"RsaPublicKey",
            r"Pkcs1v15Encrypt", r"Pkcs1v15Sign",
        ]
    },
    "ECC": {
        "severity": "CRITICAL",
        "replacement": "CRYSTALS-Dilithium (ML-DSA FIPS 204)",
        "patterns": [
            r"ECDSA", r"ECDH",
            r"from cryptography\.hazmat\.primitives\.asymmetric import ec",
            r"ec\.generate_private_key",
            r"ec\.SECP256R1", r"ec\.SECP384R1", r"ec\.SECP521R1",
            r"ec\.SECP256K1",
            r"createECDH", r"generateKeyPairSync\s*\(\s*['\"]ec['\"]",
            r"KeyPairGenerator\.getInstance\s*\(\s*['\"]EC['\"]",
            r"ECPublicKeySpec", r"ECPrivateKeySpec",
            r"elliptic\.ec", r"secp256k1",
            r"prime256v1", r"brainpool",
            r"curve25519", r"x25519",
            r"OpenSSL::PKey::EC",
            # Go
            r"elliptic\.P256", r"elliptic\.P384", r"elliptic\.P521",
            r"ecdsa\.GenerateKey", r"ecdsa\.Sign", r"ecdsa\.Verify",
            # Rust
            r"p256::SecretKey", r"p384::SecretKey",
            r"k256::SecretKey", r"ecdsa::SigningKey",
        ]
    },
    "DH": {
        "severity": "HIGH",
        "replacement": "CRYSTALS-Kyber (ML-KEM FIPS 203)",
        "patterns": [
            r"DHE", r"DiffieHellman",
            r"from cryptography\.hazmat\.primitives\.asymmetric import dh",
            r"dh\.generate_parameters",
            r"getDiffieHellman", r"createDiffieHellman",
            r"KeyPairGenerator\.getInstance\s*\(\s*['\"]DH['\"]",
            r"DHPublicKeySpec", r"DHPrivateKeySpec",
            r"javax\.crypto\.interfaces\.DHKey",
            # Go
            r"dh\.GenerateKey",
        ]
    },
    "DSA": {
        "severity": "HIGH",
        "replacement": "CRYSTALS-Dilithium (ML-DSA FIPS 204)",
        "patterns": [
            r"from Crypto\.PublicKey import DSA",
            r"from cryptography\.hazmat\.primitives\.asymmetric import dsa",
            r"dsa\.generate_private_key",
            r"DSAKey", r"DSS\.",
            r"KeyPairGenerator\.getInstance\s*\(\s*['\"]DSA['\"]",
            r"generateKeyPairSync\s*\(\s*['\"]dsa['\"]",
            r"java\.security\.interfaces\.DSAKey",
            # Go
            r"dsa\.GenerateKey", r"dsa\.Sign",
        ]
    },
    "MD5": {
        "severity": "MEDIUM",
        "replacement": "SHA-3-256 or BLAKE3",
        "patterns": [
            r"hashlib\.md5",
            r"MD5\(\)", r"new MD5",
            r"createHash\s*\(\s*['\"]md5['\"]",
            r"DigestUtils\.md5",
            r"MessageDigest\.getInstance\s*\(\s*['\"]MD5['\"]",
            r"Digest::MD5",
            r"md5sum", r"md5_hex",
            r"crypto\.createHash\s*\(\s*['\"]md5['\"]",
            r"OpenSSL::Digest::MD5",
            # Go
            r"md5\.New\(\)", r"md5\.Sum",
            # Rust
            r"md5::compute", r"Md5::new",
        ]
    },
    "SHA1": {
        "severity": "MEDIUM",
        "replacement": "SHA-3-256 or BLAKE3",
        "patterns": [
            r"hashlib\.sha1",
            r"SHA1\(\)", r"new SHA1",
            r"createHash\s*\(\s*['\"]sha1['\"]",
            r"DigestUtils\.sha1",
            r"MessageDigest\.getInstance\s*\(\s*['\"]SHA-1['\"]",
            r"Digest::SHA1",
            r"sha1sum", r"sha1_hex",
            r"crypto\.createHash\s*\(\s*['\"]sha1['\"]",
            r"OpenSSL::Digest::SHA1",
            # Go
            r"sha1\.New\(\)", r"sha1\.Sum",
            # Rust
            r"sha1::Sha1", r"Sha1::new",
        ]
    },
    "SHA256_SIGNED": {
        "severity": "MEDIUM",
        "replacement": "SHA-3-256 (SHA-2 is quantum-weakened for signatures)",
        "patterns": [
            r"sha256WithRSAEncryption",
            r"SHA256withRSA",
            r"SHA256withECDSA",
            r"SHA256withDSA",
            r"RS256", r"ES256", r"PS256",
        ]
    },
    "RC4": {
        "severity": "CRITICAL",
        "replacement": "AES-256-GCM or ChaCha20-Poly1305",
        "patterns": [
            r"RC4", r"ARC4", r"arc4",
            r"Cipher\.getInstance\s*\(\s*['\"]RC4['\"]",
            r"from Crypto\.Cipher import ARC4",
            r"crypto\.createCipheriv\s*\(\s*['\"]rc4['\"]",
            # Go
            r"rc4\.NewCipher",
            # Rust
            r"Rc4::new",
        ]
    },
    "DES": {
        "severity": "CRITICAL",
        "replacement": "AES-256-GCM or ChaCha20-Poly1305",
        "patterns": [
            r"3DES", r"TripleDES", r"DESede",
            r"from Crypto\.Cipher import DES",
            r"DES3\.new", r"DES\.new",
            r"Cipher\.getInstance\s*\(\s*['\"]DES",
            r"crypto\.createCipheriv\s*\(\s*['\"]des",
            r"OpenSSL::Cipher::DES",
            # Go
            r"des\.NewCipher", r"des\.NewTripleDESCipher",
            # Rust
            r"Des::new", r"TdesEde3::new",
        ]
    },
    "ECB_MODE": {
        "severity": "HIGH",
        "replacement": "AES-256-GCM or ChaCha20-Poly1305",
        "patterns": [
            r"AES\.MODE_ECB",
            r"DES\.MODE_ECB",
            r"Cipher\.getInstance\s*\(\s*['\"][^'\"]+/ECB",
            r"mode\s*=\s*['\"]?ECB",
            r"AES/ECB",
            r"createCipheriv\s*\(\s*['\"]aes-\d+-ecb",
        ]
    },
    "WEAK_TLS": {
        "severity": "HIGH",
        "replacement": "TLS 1.3 minimum",
        "patterns": [
            r"ssl\.PROTOCOL_SSLv2",
            r"ssl\.PROTOCOL_SSLv3",
            r"ssl\.PROTOCOL_TLSv1\b",
            r"ssl\.PROTOCOL_TLSv1_1",
            r"SSLv2", r"SSLv3",
            r"TLSv1\b", r"TLSv1\.1",
            r"secureProtocol.*SSLv",
            r"minVersion.*TLSv1\b",
            r"TLS_RSA_WITH",
            # Go
            r"tls\.VersionTLS10", r"tls\.VersionTLS11",
            r"tls\.VersionSSL30",
            # Rust
            r"ProtocolVersion::SSLv3",
            r"ProtocolVersion::TLSv1_0",
            r"ProtocolVersion::TLSv1_1",
        ]
    },
    "WEAK_KEY_SIZE": {
        "severity": "HIGH",
        "replacement": "RSA-4096 minimum or migrate to PQC",
        "patterns": [
            r"RSA\.generate\s*\(\s*[5-9]\d{2}\s*\)",
            r"RSA\.generate\s*\(\s*1[0-9]{3}\s*\)",
            r"RSA\.generate\s*\(\s*2048\s*\)",
            r"generate_private_key\s*\([^)]*key_size\s*=\s*(?:512|1024|2048)",
            r"KeySize\s*=\s*(?:512|1024|2048)",
            r"key_size\s*=\s*(?:512|1024|2048)",
            # Go
            r"rsa\.GenerateKey\s*\([^,]+,\s*(?:512|1024|2048)\s*\)",
            # Rust
            r"RsaPrivateKey::new\s*\([^,]+,\s*(?:512|1024|2048)\s*\)",
        ]
    },
    "HARDCODED_SECRET": {
        "severity": "HIGH",
        "replacement": "Use environment variables or a secret manager (AWS Secrets Manager, HashiCorp Vault)",
        "patterns": [
            r"(?i)password\s*=\s*['\"][^'\"]{4,}['\"]",
            r"(?i)secret\s*=\s*['\"][^'\"]{4,}['\"]",
            r"(?i)api_key\s*=\s*['\"][^'\"]{4,}['\"]",
            r"(?i)private_key\s*=\s*['\"][^'\"]{4,}['\"]",
            r"(?i)SECRET_KEY\s*=\s*['\"][^'\"]{4,}['\"]",
            r"(?i)token\s*=\s*['\"][^'\"]{8,}['\"]",
            r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
            r"(?i)aws_secret_access_key\s*=\s*['\"][^'\"]{4,}['\"]",
        ]
    },
    "WEAK_RANDOM": {
        "severity": "MEDIUM",
        "replacement": "secrets module (Python) or crypto.getRandomValues() (JS)",
        "patterns": [
            r"random\.random\(\)",
            r"random\.randint",
            r"random\.choice",
            r"Math\.random\(\)",
            r"new Random\(\)",
            r"java\.util\.Random",
            r"rand\(\)",
            r"mt_rand\(\)",
            # Go
            r"math/rand",
            r"rand\.Intn", r"rand\.Float",
            # Rust
            r"rand::thread_rng",
            r"SmallRng::new",
        ]
    },
    "JWT_NONE_ALG": {
        "severity": "CRITICAL",
        "replacement": "Use RS256 with post-quantum safe keys or EdDSA",
        "patterns": [
            r"algorithm\s*=\s*['\"]none['\"]",
            r"alg.*none",
            r"jwt\.decode\([^)]*verify\s*=\s*False",
            r"jwt\.decode\([^)]*options\s*=\s*\{[^}]*verify_signature.*False",
        ]
    },
    "BLOWFISH": {
        "severity": "HIGH",
        "replacement": "AES-256-GCM",
        "patterns": [
            r"Blowfish", r"blowfish",
            r"Cipher\.getInstance\s*\(\s*['\"]Blowfish",
            r"from Crypto\.Cipher import Blowfish",
            # Go
            r"golang\.org/x/crypto/blowfish",
            # Rust
            r"blowfish::Blowfish",
        ]
    },
    "MD4": {
        "severity": "CRITICAL",
        "replacement": "SHA-3-256 or BLAKE3",
        "patterns": [
            r"MD4", r"md4",
            r"MessageDigest\.getInstance\s*\(\s*['\"]MD4['\"]",
        ]
    },
}

SEVERITY_SCORE = {
    "CRITICAL": 10,
    "HIGH": 6,
    "MEDIUM": 3,
}