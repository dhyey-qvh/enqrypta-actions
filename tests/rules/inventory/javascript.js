const crypto = require("crypto");
const { createCipheriv, createHash } = require("node:crypto");

const BITS = 3072;

function ciphers(key, iv, name) {
  // ruleid: enqrypta.crypto.javascript.aes-cipher
  crypto.createCipheriv("aes-256-gcm", key, iv);
  // ruleid: enqrypta.crypto.javascript.aes-cipher
  createCipheriv('aes-128-cbc', key, iv);
  // ok: enqrypta.crypto.javascript.aes-cipher
  crypto.createCipheriv("chacha20-poly1305", key, iv, { authTagLength: 16 });
  // ok: enqrypta.crypto.javascript.aes-cipher
  crypto.createCipheriv(name, key, iv);
}

function rsa(publicKey, privateKey, data, options) {
  // ruleid: enqrypta.crypto.javascript.rsa-keygen
  crypto.generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 0x10001 });
  // ruleid: enqrypta.crypto.javascript.rsa-keygen
  crypto.generateKeyPair("rsa", { publicExponent: 65537, modulusLength: BITS }, () => {});
  // ruleid: enqrypta.crypto.javascript.rsa-keygen
  crypto.generateKeyPairSync("rsa", options);
  // ok: enqrypta.crypto.javascript.rsa-keygen
  crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  // ruleid: enqrypta.crypto.javascript.rsa-sign
  crypto.createSign("RSA-SHA256");
  // ruleid: enqrypta.crypto.javascript.rsa-sign
  crypto.generateKeyPairSync("rsa-pss", { modulusLength: 3072 });
  // ok: enqrypta.crypto.javascript.rsa-sign
  crypto.createSign("SHA256");
  // ruleid: enqrypta.crypto.javascript.rsa-encrypt
  crypto.publicEncrypt(publicKey, data);
  // ruleid: enqrypta.crypto.javascript.rsa-encrypt
  crypto.privateDecrypt(privateKey, data);
  // ok: enqrypta.crypto.javascript.rsa-encrypt
  crypto.publicDecrypt;
}

function agreements(prime) {
  // ruleid: enqrypta.crypto.javascript.ecdh
  crypto.createECDH("prime256v1");
  // ok: enqrypta.crypto.javascript.ecdh
  crypto.getCurves();
  // ruleid: enqrypta.crypto.javascript.dh
  crypto.createDiffieHellman(prime);
  // ruleid: enqrypta.crypto.javascript.dh
  crypto.getDiffieHellman("modp14");
  // ok: enqrypta.crypto.javascript.dh
  crypto.diffieHellman;
  // ruleid: enqrypta.crypto.javascript.ed25519
  crypto.generateKeyPairSync("ed25519");
  // ok: enqrypta.crypto.javascript.ed25519
  crypto.generateKeyPairSync("ed448");
  // ruleid: enqrypta.crypto.javascript.x25519
  crypto.generateKeyPair("x25519", {}, () => {});
  // ok: enqrypta.crypto.javascript.x25519
  crypto.generateKeyPairSync("x448");
}

async function webcrypto(raw) {
  const subtle = globalThis.crypto.subtle;
  // ruleid: enqrypta.crypto.javascript.webcrypto-rsa-encrypt
  await subtle.generateKey({ name: "RSA-OAEP", modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
  // ok: enqrypta.crypto.javascript.webcrypto-rsa-encrypt
  await subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, ["sign"]);
  // ruleid: enqrypta.crypto.javascript.webcrypto-rsa-sign
  await subtle.generateKey({ name: "RSA-PSS", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign"]);
  // ok: enqrypta.crypto.javascript.webcrypto-rsa-sign
  await subtle.generateKey({ name: "HMAC", hash: "SHA-512" }, true, ["sign"]);
  // ruleid: enqrypta.crypto.javascript.webcrypto-ecdsa
  await subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign"]);
  // ok: enqrypta.crypto.javascript.webcrypto-ecdsa
  await subtle.digest("SHA-256", raw);
  // ruleid: enqrypta.crypto.javascript.webcrypto-ecdh
  await subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, true, []);
  // ok: enqrypta.crypto.javascript.webcrypto-ecdh
  await subtle.importKey("raw", raw, { name: "HKDF" }, false, ["deriveKey"]);
  // ruleid: enqrypta.crypto.javascript.webcrypto-aes
  await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  // ruleid: enqrypta.crypto.javascript.webcrypto-aes
  await subtle.importKey("raw", raw, "AES-CBC", false, ["encrypt"]);
  // ok: enqrypta.crypto.javascript.webcrypto-aes
  await subtle.importKey("raw", raw, "PBKDF2", false, ["deriveBits"]);
  // ruleid: enqrypta.crypto.javascript.ed25519
  await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
}

function digests(data) {
  // ruleid: enqrypta.crypto.javascript.sha1
  crypto.createHash("sha1").update(data);
  // ruleid: enqrypta.crypto.javascript.sha1
  globalThis.crypto.subtle.digest("SHA-1", data);
  // ok: enqrypta.crypto.javascript.sha1
  createHash("sha256");
  // ruleid: enqrypta.crypto.javascript.md5
  createHash("md5");
  // ok: enqrypta.crypto.javascript.md5
  crypto.createHash("sha512");
}
