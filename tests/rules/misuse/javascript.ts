import * as crypto from "crypto";
import { createCipheriv, createHmac } from "node:crypto";
import https from "https";
import tls from "tls";

function weakCiphers(key: Buffer, iv: Buffer): void {
  // ruleid: enqrypta.misuse.javascript.weak-cipher-3des
  crypto.createCipheriv("des-ede3-cbc", key, iv);
  // ok: enqrypta.misuse.javascript.weak-cipher-3des
  crypto.createCipheriv("aes-256-gcm", key, iv);
  // ruleid: enqrypta.misuse.javascript.weak-cipher-des
  crypto.createCipheriv("des-cbc", key, iv);
  // ok: enqrypta.misuse.javascript.weak-cipher-des
  crypto.createCipheriv("aes-256-cbc", key, iv);
  // ruleid: enqrypta.misuse.javascript.weak-cipher-rc4
  createCipheriv("rc4", key, null);
  // ok: enqrypta.misuse.javascript.weak-cipher-rc4
  createCipheriv("chacha20-poly1305", key, iv);
  // ruleid: enqrypta.misuse.javascript.weak-cipher-blowfish
  crypto.createCipheriv("bf-cbc", key, iv);
  // ok: enqrypta.misuse.javascript.weak-cipher-blowfish
  crypto.createCipheriv("camellia-256-cbc", key, iv);
}

function modes(key: Buffer, iv: Buffer): void {
  // ruleid: enqrypta.misuse.javascript.ecb-mode
  crypto.createCipheriv("aes-128-ecb", key, null);
  // ok: enqrypta.misuse.javascript.ecb-mode
  crypto.createCipheriv("aes-128-ctr", key, iv);
}

function weakHashes(key: Buffer, data: Buffer, privateKey: crypto.KeyObject): void {
  // ruleid: enqrypta.misuse.javascript.sha1-signature
  crypto.createSign("RSA-SHA1");
  // ruleid: enqrypta.misuse.javascript.sha1-signature
  crypto.sign("sha1", data, privateKey);
  // ok: enqrypta.misuse.javascript.sha1-signature
  crypto.sign("sha256", data, privateKey);
  // ruleid: enqrypta.misuse.javascript.md5-signature-or-mac
  createHmac("md5", key);
  // ok: enqrypta.misuse.javascript.md5-signature-or-mac
  createHmac("sha256", key);
}

function randomness(): string[] {
  // ruleid: enqrypta.misuse.javascript.insecure-random
  const resetToken = Math.random().toString(36).slice(2);
  // ruleid: enqrypta.misuse.javascript.insecure-random
  let api_key = Math.floor(Math.random() * 1e16).toString(16);
  // ok: enqrypta.misuse.javascript.insecure-random
  const sessionToken = crypto.randomBytes(32).toString("hex");
  // ok: enqrypta.misuse.javascript.insecure-random
  const jitterMs = Math.random() * 100;
  return [resetToken, api_key, sessionToken, String(jitterMs)];
}

async function fixedIvs(key: Buffer, iv: Buffer, cryptoKey: CryptoKey, data: Uint8Array): Promise<void> {
  // ruleid: enqrypta.misuse.javascript.hardcoded-iv
  crypto.createCipheriv("aes-256-cbc", key, "1234567890123456");
  // ruleid: enqrypta.misuse.javascript.hardcoded-iv
  createCipheriv("aes-256-gcm", key, Buffer.alloc(12));
  // ruleid: enqrypta.misuse.javascript.hardcoded-iv
  await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(12) }, cryptoKey, data);
  // ok: enqrypta.misuse.javascript.hardcoded-iv
  crypto.createCipheriv("aes-256-gcm", key, iv);
  // ok: enqrypta.misuse.javascript.hardcoded-iv
  await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, data);
}

function fixedKeys(key: Buffer, iv: Buffer): void {
  // ruleid: enqrypta.misuse.javascript.hardcoded-key
  crypto.createCipheriv("aes-128-gcm", "0123456789abcdef", iv);
  // ruleid: enqrypta.misuse.javascript.hardcoded-key
  createCipheriv("aes-256-gcm", Buffer.from("0123456789abcdef0123456789abcdef", "utf8"), iv);
  // ruleid: enqrypta.misuse.javascript.hardcoded-key
  createHmac("sha256", "webhook-secret");
  // ok: enqrypta.misuse.javascript.hardcoded-key
  createHmac("sha256", key);
}

function tlsOptions(): void {
  // ruleid: enqrypta.misuse.javascript.tls-verify-disabled
  new https.Agent({ keepAlive: true, rejectUnauthorized: false });
  // ruleid: enqrypta.misuse.javascript.tls-verify-disabled
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  // ok: enqrypta.misuse.javascript.tls-verify-disabled
  new https.Agent({ rejectUnauthorized: true });
  // ruleid: enqrypta.misuse.javascript.weak-tls-version
  tls.connect({ host: "example.com", minVersion: "TLSv1" });
  // ruleid: enqrypta.misuse.javascript.weak-tls-version
  tls.createSecureContext({ secureProtocol: "TLSv1_method" });
  // ok: enqrypta.misuse.javascript.weak-tls-version
  tls.connect({ host: "example.com", minVersion: "TLSv1.2" });
}
