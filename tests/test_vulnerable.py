from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
import hashlib

# RSA key generation - QUANTUM VULNERABLE
key = RSA.generate(2048)
cipher = PKCS1_OAEP.new(key)

# MD5 hashing - QUANTUM VULNERABLE
data = b"secret password"
md5_hash = hashlib.md5(data).hexdigest()

# SHA1 hashing - QUANTUM VULNERABLE
sha1_hash = hashlib.sha1(data).hexdigest()

# ECDSA - QUANTUM VULNERABLE
from Crypto.PublicKey import ECC
ecc_key = ECC.generate(curve='P-256')