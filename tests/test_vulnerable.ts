import * as crypto from 'crypto';
import { NodeRSA } from 'node-rsa';

// RSA - QUANTUM VULNERABLE
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

// ECC - QUANTUM VULNERABLE
const ec = crypto.createECDH('secp256k1');
ec.generateKeys();

// MD5 - QUANTUM VULNERABLE
const md5Hash = crypto.createHash('md5').update('password').digest('hex');

// SHA1 - QUANTUM VULNERABLE
const sha1Hash = crypto.createHash('sha1').update('data').digest('hex');