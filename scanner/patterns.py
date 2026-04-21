VULNERABLE_PATTERNS = {
    "RSA": {
        "severity": "CRITICAL",
        "replacement": "CRYSTALS-Kyber",
        "patterns": [
            "RSA", "rsa", "RSAKey", "RSA.new",
            "RSA.generate", "PKCS1_OAEP", "PKCS1_v1_5",
        ]
    },
    "ECC": {
        "severity": "CRITICAL",
        "replacement": "CRYSTALS-Dilithium",
        "patterns": [
            "EC", "ECC", "ECDSA", "ECDH",
            "elliptic", "secp256k1", "prime256v1",
        ]
    },
    "DH": {
        "severity": "HIGH",
        "replacement": "CRYSTALS-Kyber",
        "patterns": [
            "DH", "DHE", "DiffieHellman",
            "diffie-hellman",
        ]
    },
    "DSA": {
        "severity": "HIGH",
        "replacement": "CRYSTALS-Dilithium",
        "patterns": [
            "DSA", "DSAKey", "DSS",
        ]
    },
    "MD5": {
        "severity": "MEDIUM",
        "replacement": "SHA-3 or SPHINCS+",
        "patterns": [
            "MD5", "md5", "hashlib.md5",
        ]
    },
    "SHA1": {
        "severity": "MEDIUM",
        "replacement": "SHA-3 or SPHINCS+",
        "patterns": [
            "SHA1", "sha1", "hashlib.sha1",
        ]
    },
}

JS_PATTERNS = {
    "RSA": ["crypto.generateKeyPairSync.*rsa", "new NodeRSA", "forge.pki.rsa"],
    "ECC": ["crypto.createECDH", "elliptic", "secp256k1"],
    "DH": ["crypto.getDiffieHellman", "crypto.createDiffieHellman"],
    "MD5": ["crypto.createHash.*md5", "md5("],
    "SHA1": ["crypto.createHash.*sha1", "sha1("],
}

TS_PATTERNS = {
    "RSA": ["generateKeyPairSync.*rsa", "new NodeRSA", "forge.pki.rsa"],
    "ECC": ["createECDH", "elliptic", "secp256k1"],
    "DH": ["getDiffieHellman", "createDiffieHellman"],
    "MD5": ["createHash.*md5", "md5("],
    "SHA1": ["createHash.*sha1", "sha1("],
}

JAVA_PATTERNS = {
    "RSA": ["KeyPairGenerator.*RSA", "RSAPublicKeySpec", "java.security.interfaces.RSAKey"],
    "ECC": ["KeyPairGenerator.*EC", "ECPublicKeySpec", "java.security.interfaces.ECKey"],
    "DH": ["KeyPairGenerator.*DH", "DHPublicKeySpec", "javax.crypto.interfaces.DHKey"],
    "MD5": ["MessageDigest.*MD5", "DigestUtils.md5"],
    "SHA1": ["MessageDigest.*SHA-1", "DigestUtils.sha1"],
}

SEVERITY_SCORE = {
    "CRITICAL": 10,
    "HIGH": 6,
    "MEDIUM": 3,
}