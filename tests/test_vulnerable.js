const crypto = require('crypto');
const NodeRSA = require('node-rsa');
const elliptic = require('elliptic');

// RSA - QUANTUM VULNERABLE
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

// ECC - QUANTUM VULNERABLE
const ec = new elliptic.ec('secp256k1');
const key = ec.genKeyPair();

// DH - QUANTUM VULNERABLE
const dh = crypto.createDiffieHellman(2048);
dh.generateKeys();

// MD5 - QUANTUM VULNERABLE
const md5Hash = crypto.createHash('md5').update('password').digest('hex');

// SHA1 - QUANTUM VULNERABLE
const sha1Hash = crypto.createHash('sha1').update('data').digest('hex');