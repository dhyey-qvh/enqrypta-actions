import hashlib
import hmac
import random
import secrets
import ssl

import requests
import urllib3
from Crypto.Cipher import AES, ARC4, DES, DES3, Blowfish
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

STATIC_IV = b"0123456789abcdef"


def weak_ciphers(key):
    # ruleid: enqrypta.misuse.python.weak-cipher-3des
    algorithms.TripleDES(key)
    # ruleid: enqrypta.misuse.python.weak-cipher-3des
    DES3.new(key, DES3.MODE_CBC)
    # ok: enqrypta.misuse.python.weak-cipher-3des
    algorithms.AES(key)
    # ruleid: enqrypta.misuse.python.weak-cipher-des
    DES.new(key, DES.MODE_CBC)
    # ok: enqrypta.misuse.python.weak-cipher-des
    AES.new(key, AES.MODE_GCM)
    # ruleid: enqrypta.misuse.python.weak-cipher-rc4
    algorithms.ARC4(key)
    # ruleid: enqrypta.misuse.python.weak-cipher-rc4
    ARC4.new(key)
    # ok: enqrypta.misuse.python.weak-cipher-rc4
    algorithms.ChaCha20(key, b"n" * 16)
    # ruleid: enqrypta.misuse.python.weak-cipher-blowfish
    Blowfish.new(key, Blowfish.MODE_CBC)
    # ok: enqrypta.misuse.python.weak-cipher-blowfish
    algorithms.Camellia(key)


def modes_of_operation(key, iv):
    # ruleid: enqrypta.misuse.python.ecb-mode
    modes.ECB()
    # ruleid: enqrypta.misuse.python.ecb-mode
    AES.new(key, AES.MODE_ECB)
    # ok: enqrypta.misuse.python.ecb-mode
    modes.CBC(iv)
    # ok: enqrypta.misuse.python.ecb-mode
    AES.new(key, AES.MODE_GCM)


def weak_hash_in_context(key, message):
    # ruleid: enqrypta.misuse.python.sha1-signature
    key.sign(message, ec.ECDSA(hashes.SHA1()))
    # ruleid: enqrypta.misuse.python.sha1-signature
    key.sign(message, padding_scheme, hashes.SHA1())
    # ok: enqrypta.misuse.python.sha1-signature
    key.sign(message, ec.ECDSA(hashes.SHA256()))
    # ruleid: enqrypta.misuse.python.md5-signature-or-mac
    hmac.new(key, message, hashlib.md5)
    # ruleid: enqrypta.misuse.python.md5-signature-or-mac
    hmac.new(key, message, digestmod="md5")
    # ruleid: enqrypta.misuse.python.md5-signature-or-mac
    key.sign(message, padding_scheme, hashes.MD5())
    # ok: enqrypta.misuse.python.md5-signature-or-mac
    hmac.new(key, message, hashlib.sha256)


def randomness(alphabet):
    # ruleid: enqrypta.misuse.python.insecure-random
    session_token = random.getrandbits(128)
    # ruleid: enqrypta.misuse.python.insecure-random
    api_key = "".join(random.choice(alphabet) for _ in range(32))
    # ruleid: enqrypta.misuse.python.insecure-random
    iv = random.randbytes(16)
    # ok: enqrypta.misuse.python.insecure-random
    session_token = secrets.token_hex(16)
    # ok: enqrypta.misuse.python.insecure-random
    delay = random.uniform(0.1, 0.5)
    # ok: enqrypta.misuse.python.insecure-random
    monkey = random.choice(alphabet)
    return session_token, api_key, iv, delay, monkey


def fixed_ivs(key, iv):
    # ruleid: enqrypta.misuse.python.hardcoded-iv
    modes.CBC(b"\x00" * 16)
    # ruleid: enqrypta.misuse.python.hardcoded-iv
    modes.GCM(b"fixed-nonce!")
    # ruleid: enqrypta.misuse.python.hardcoded-iv
    modes.CBC(bytes(16))
    # ruleid: enqrypta.misuse.python.hardcoded-iv
    modes.CBC(STATIC_IV)
    # ruleid: enqrypta.misuse.python.hardcoded-iv
    AES.new(key, AES.MODE_CBC, iv=b"1234567890123456")
    # ruleid: enqrypta.misuse.python.hardcoded-iv
    AES.new(key, AES.MODE_GCM, nonce=b"123456789012")
    # ok: enqrypta.misuse.python.hardcoded-iv
    modes.CBC(iv)
    # ok: enqrypta.misuse.python.hardcoded-iv
    AES.new(key, AES.MODE_GCM, nonce=secrets.token_bytes(12))


def fixed_keys(key, message):
    # ruleid: enqrypta.misuse.python.hardcoded-key
    algorithms.AES(b"0123456789abcdef0123456789abcdef")
    # ruleid: enqrypta.misuse.python.hardcoded-key
    AESGCM(b"0123456789abcdef")
    # ruleid: enqrypta.misuse.python.hardcoded-key
    AES.new(b"0123456789abcdef", AES.MODE_GCM)
    # ruleid: enqrypta.misuse.python.hardcoded-key
    hmac.new(b"webhook-secret", message, hashlib.sha256)
    # ok: enqrypta.misuse.python.hardcoded-key
    AESGCM(key)
    # ok: enqrypta.misuse.python.hardcoded-key
    hmac.new(key, message, hashlib.sha256)


def tls_verification(url, session):
    # ruleid: enqrypta.misuse.python.tls-verify-disabled
    requests.get(url, verify=False)
    # ruleid: enqrypta.misuse.python.tls-verify-disabled
    session.post(url, json={}, verify=False)
    # ruleid: enqrypta.misuse.python.tls-verify-disabled
    ssl._create_unverified_context()
    context = ssl.create_default_context()
    # ruleid: enqrypta.misuse.python.tls-verify-disabled
    context.check_hostname = False
    # ruleid: enqrypta.misuse.python.tls-verify-disabled
    context.verify_mode = ssl.CERT_NONE
    # ruleid: enqrypta.misuse.python.tls-verify-disabled
    urllib3.PoolManager(cert_reqs="CERT_NONE")
    # ok: enqrypta.misuse.python.tls-verify-disabled
    requests.get(url, verify=True)
    # ok: enqrypta.misuse.python.tls-verify-disabled
    session.merge(url, verify=False)
    # ok: enqrypta.misuse.python.tls-verify-disabled
    context.verify_mode = ssl.CERT_REQUIRED


def tls_versions():
    # ruleid: enqrypta.misuse.python.weak-tls-version
    ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    # ruleid: enqrypta.misuse.python.weak-tls-version
    ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
    context = ssl.create_default_context()
    # ruleid: enqrypta.misuse.python.weak-tls-version
    context.minimum_version = ssl.TLSVersion.TLSv1
    # ok: enqrypta.misuse.python.weak-tls-version
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # ok: enqrypta.misuse.python.weak-tls-version
    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
