import hashlib

import oqs
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import MD5, SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, ec, ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

KEY_BITS = 3072


def rsa_keys(bits):
    # ruleid: enqrypta.crypto.python.rsa-keygen
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # ruleid: enqrypta.crypto.python.rsa-keygen
    rsa.generate_private_key(65537, KEY_BITS)
    # ruleid: enqrypta.crypto.python.rsa-keygen
    RSA.generate(bits)
    # ok: enqrypta.crypto.python.rsa-keygen
    ec.generate_private_key(ec.SECP384R1())


def rsa_use(private_key, public_key, message, signature):
    # ruleid: enqrypta.crypto.python.rsa-encrypt
    public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    # ruleid: enqrypta.crypto.python.rsa-encrypt
    private_key.decrypt(message, padding.PKCS1v15())
    # ok: enqrypta.crypto.python.rsa-encrypt
    private_key.encrypt(message)
    # ruleid: enqrypta.crypto.python.rsa-encrypt-oaep
    PKCS1_OAEP.new(public_key)
    # ok: enqrypta.crypto.python.rsa-encrypt-oaep
    public_key.export_key()
    # ruleid: enqrypta.crypto.python.rsa-sign
    private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    # ruleid: enqrypta.crypto.python.rsa-sign
    public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    # ok: enqrypta.crypto.python.rsa-sign
    private_key.sign(message)
    # ruleid: enqrypta.crypto.python.rsa-sign-pycryptodome
    pkcs1_15.new(private_key)
    # ruleid: enqrypta.crypto.python.rsa-sign-pycryptodome
    pss.new(private_key)
    # ok: enqrypta.crypto.python.rsa-sign-pycryptodome
    private_key.export_key()


def ec_use(private_key, peer, message, signature):
    # ruleid: enqrypta.crypto.python.ecdsa-sign
    private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    # ruleid: enqrypta.crypto.python.ecdsa-sign
    peer.verify(signature, message, ec.ECDSA(hashes.SHA384()))
    # ok: enqrypta.crypto.python.ecdsa-sign
    private_key.sign(message, signature)
    # ruleid: enqrypta.crypto.python.ecdh
    private_key.exchange(ec.ECDH(), peer)
    # ok: enqrypta.crypto.python.ecdh
    private_key.exchange(peer)
    # ruleid: enqrypta.crypto.python.x25519
    x25519.X25519PrivateKey.generate()
    # ok: enqrypta.crypto.python.x25519
    x25519.X25519PublicKey.from_public_bytes(signature)
    # ruleid: enqrypta.crypto.python.ed25519
    ed25519.Ed25519PrivateKey.generate()
    # ok: enqrypta.crypto.python.ed25519
    ed25519.Ed25519PublicKey.from_public_bytes(signature)
    # ruleid: enqrypta.crypto.python.dh
    dh.generate_parameters(generator=2, key_size=2048)
    # ok: enqrypta.crypto.python.dh
    dh.DHParameterNumbers(23, 5)


def symmetric(key, iv, data):
    # ruleid: enqrypta.crypto.python.aes
    Cipher(algorithms.AES(key), modes.GCM(iv))
    # ruleid: enqrypta.crypto.python.aes
    AES.new(key, AES.MODE_CBC, iv)
    # ok: enqrypta.crypto.python.aes
    Cipher(algorithms.ChaCha20(key, iv), mode=None)
    # ruleid: enqrypta.crypto.python.aes-gcm
    AESGCM(key)
    # ok: enqrypta.crypto.python.aes-gcm
    ChaCha20Poly1305(key)


def digests(data, name):
    # ruleid: enqrypta.crypto.python.sha1
    hashlib.sha1(data)
    # ruleid: enqrypta.crypto.python.sha1
    hashes.SHA1()
    # ruleid: enqrypta.crypto.python.sha1
    hashlib.new("sha1", data)
    # ruleid: enqrypta.crypto.python.sha1
    SHA1.new(data)
    # ok: enqrypta.crypto.python.sha1
    hashlib.sha256(data)
    # ok: enqrypta.crypto.python.sha1
    hashlib.new(name, data)
    # ruleid: enqrypta.crypto.python.md5
    hashlib.md5(data)
    # ruleid: enqrypta.crypto.python.md5
    hashlib.new("MD5")
    # ruleid: enqrypta.crypto.python.md5
    MD5.new(data)
    # ok: enqrypta.crypto.python.md5
    hashlib.sha3_256(data)


def post_quantum():
    # ruleid: enqrypta.crypto.python.ml-kem
    oqs.KeyEncapsulation("ML-KEM-768")
    # ok: enqrypta.crypto.python.ml-kem
    oqs.KeyEncapsulation("FrodoKEM-640-AES")
    # ruleid: enqrypta.crypto.python.ml-dsa
    oqs.Signature("ML-DSA-65")
    # ok: enqrypta.crypto.python.ml-dsa
    oqs.Signature("Falcon-512")
