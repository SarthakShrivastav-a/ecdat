// truth: MD5 hash, AES-256-GCM cipher, RSA-2048 keypair (node crypto), RSA-1024 keypair (node-forge), HMAC-SHA256
const crypto = require('crypto');
const forge = require('node-forge');

function etag(body) {
  return crypto.createHash('md5').update(body).digest('hex');
}

function encryptSession(key, iv, data) {
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([c.update(data), c.final()]);
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const legacyPair = forge.pki.rsa.generateKeyPair(1024);
const mac = crypto.createHmac('sha256', 'secret').update('x').digest('hex');

module.exports = { etag, encryptSession, publicKey, privateKey, legacyPair, mac };
