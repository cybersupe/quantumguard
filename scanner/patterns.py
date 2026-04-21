VULNERABLE_PATTERNS = {
    "RSA": {
        "severity": "CRITICAL",
        "replacement": "CRYSTALS-Kyber",
        "patterns": [
            "RSA", "rsa", "RSAKey", "RSA.new",
            "RSA.generate", "PKCS1_OAEP", "PKCS1_v1_5",
            "RSA.import_key", "RSA.export_key",
            "generateKeyPairSync.*rsa",
            "KeyPairGenerator.*RSA",
            "RSAPublicKeySpec", "RSAPrivateKeySpec",
            "forge.pki.rsa", "NodeRSA",
        ]
    },
    "ECC": {
        "severity": "CRITICAL",
        "replacement": "CRYSTALS-Dilithium",
        "patterns": [
            "EC", "ECC", "ECDSA", "ECDH",
            "elliptic", "secp256k1", "prime256v1",
            "createECDH", "generateKeyPairSync.*ec",
            "KeyPairGenerator.*EC", "ECPublicKeySpec",
            "brainpool", "curve25519",
        ]
    },
    "DH": {
        "severity": "HIGH",
        "replacement": "CRYSTALS-Kyber",
        "patterns": [
            "DH", "DHE", "DiffieHellman",
            "diffie-hellman", "getDiffieHellman",
            "createDiffieHellman", "KeyPairGenerator.*DH",
            "DHPublicKeySpec",
        ]
    },
    "DSA": {
        "severity": "HIGH",
        "replacement": "CRYSTALS-Dilithium",
        "patterns": [
            "DSA", "DSAKey", "DSS",
            "KeyPairGenerator.*DSA",
            "generateKeyPairSync.*dsa",
        ]
    },
    "MD5": {
        "severity": "MEDIUM",
        "replacement": "SHA-3 or SPHINCS+",
        "patterns": [
            "MD5", "md5", "hashlib.md5",
            "createHash.*md5", "DigestUtils.md5",
            "MessageDigest.*MD5",
        ]
    },
    "SHA1": {
        "severity": "MEDIUM",
        "replacement": "SHA-3 or SPHINCS+",
        "patterns": [
            "SHA1", "sha1", "hashlib.sha1",
            "createHash.*sha1", "DigestUtils.sha1",
            "MessageDigest.*SHA-1",
        ]
    },
    "HARDCODED_SECRET": {
        "severity": "HIGH",
        "replacement": "Use environment variables or secret manager",
        "patterns": [
            "password.*=.*['\"]\\w+['\"]",
            "secret.*=.*['\"]\\w+['\"]",
            "api_key.*=.*['\"]\\w+['\"]",
            "private_key.*=.*['\"]\\w+['\"]",
            "SECRET_KEY.*=.*['\"]\\w+['\"]",
        ]
    },
    "ECB_MODE": {
        "severity": "HIGH",
        "replacement": "AES-GCM or ChaCha20-Poly1305",
        "patterns": [
            "AES.MODE_ECB", "Cipher.MODE_ECB",
            "ECB", "mode.*ecb", "ecb.*mode",
        ]
    },
    "WEAK_TLS": {
        "severity": "HIGH",
        "replacement": "TLS 1.3",
        "patterns": [
            "SSLv2", "SSLv3", "TLSv1", "TLSv1.1",
            "ssl.PROTOCOL_SSLv2", "ssl.PROTOCOL_SSLv3",
            "ssl.PROTOCOL_TLSv1",
            "PROTOCOL_TLS", "TLS_RSA",
        ]
    },
    "RC4": {
        "severity": "CRITICAL",
        "replacement": "AES-256-GCM",
        "patterns": [
            "RC4", "rc4", "ARC4", "arc4",
            "Cipher.*RC4",
        ]
    },
    "DES": {
        "severity": "CRITICAL",
        "replacement": "AES-256-GCM",
        "patterns": [
            "DES", "3DES", "TripleDES", "DESede",
            "Cipher.*DES", "des.*mode",
        ]
    },
}

JS_PATTERNS = {
    "RSA": ["crypto.generateKeyPairSync.*rsa", "new NodeRSA", "forge.pki.rsa"],
    "ECC": ["crypto.createECDH", "elliptic", "secp256k1"],
    "DH": ["crypto.getDiffieHellman", "crypto.createDiffieHellman"],
    "MD5": ["crypto.createHash.*md5", "md5("],
    "SHA1": ["crypto.createHash.*sha1", "sha1("],
    "ECB_MODE": ["AES.MODE_ECB", "mode.*ecb"],
    "WEAK_TLS": ["SSLv2", "SSLv3", "TLSv1"],
    "RC4": ["RC4", "ARC4"],
    "DES": ["DES", "3DES", "TripleDES"],
}

TS_PATTERNS = {
    "RSA": ["generateKeyPairSync.*rsa", "new NodeRSA", "forge.pki.rsa"],
    "ECC": ["createECDH", "elliptic", "secp256k1"],
    "DH": ["getDiffieHellman", "createDiffieHellman"],
    "MD5": ["createHash.*md5", "md5("],
    "SHA1": ["createHash.*sha1", "sha1("],
    "ECB_MODE": ["AES.MODE_ECB", "mode.*ecb"],
    "WEAK_TLS": ["SSLv2", "SSLv3", "TLSv1"],
    "RC4": ["RC4", "ARC4"],
    "DES": ["DES", "3DES", "TripleDES"],
}

JAVA_PATTERNS = {
    "RSA": ["KeyPairGenerator.*RSA", "RSAPublicKeySpec", "java.security.interfaces.RSAKey"],
    "ECC": ["KeyPairGenerator.*EC", "ECPublicKeySpec", "java.security.interfaces.ECKey"],
    "DH": ["KeyPairGenerator.*DH", "DHPublicKeySpec", "javax.crypto.interfaces.DHKey"],
    "MD5": ["MessageDigest.*MD5", "DigestUtils.md5"],
    "SHA1": ["MessageDigest.*SHA-1", "DigestUtils.sha1"],
    "ECB_MODE": ["Cipher.MODE_ECB", "AES/ECB"],
    "WEAK_TLS": ["SSLv2", "SSLv3", "TLSv1"],
    "DES": ["DESede", "DES", "Cipher.*DES"],
}

SEVERITY_SCORE = {
    "CRITICAL": 10,
    "HIGH": 6,
    "MEDIUM": 3,
}