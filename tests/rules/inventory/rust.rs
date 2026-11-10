mod dalek {
    use ed25519_dalek::SigningKey;

    fn keys(rng: &mut OsRng, seed: &[u8; 32]) {
        // ruleid: enqrypta.crypto.rust.ed25519
        let a = SigningKey::from_bytes(seed);
        // ok: enqrypta.crypto.rust.ed25519
        let b = SigningKey::verifying_key(&a);
    }
}

use p256::ecdh::EphemeralSecret;
use p384::ecdsa::SigningKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use x25519_dalek::StaticSecret;

const KEY_BITS: usize = 4096;

fn rsa_keys(rng: &mut OsRng, bits: usize) {
    // ruleid: enqrypta.crypto.rust.rsa-keygen
    let a = RsaPrivateKey::new(rng, 2048);
    // ruleid: enqrypta.crypto.rust.rsa-keygen
    let b = rsa::RsaPrivateKey::new(rng, KEY_BITS);
    // ruleid: enqrypta.crypto.rust.rsa-keygen
    let c = Rsa::generate(bits as u32);
    // ok: enqrypta.crypto.rust.rsa-keygen
    let d = RsaPublicKey::from(&a);
}

fn rsa_use(key: &RsaPrivateKey, public: &RsaPublicKey, rng: &mut OsRng, data: &[u8], openssl_key: &Rsa<Private>) {
    // ruleid: enqrypta.crypto.rust.rsa-encrypt
    let a = public.encrypt(rng, Oaep::new::<Sha256>(), data);
    // ruleid: enqrypta.crypto.rust.rsa-encrypt
    let b = key.decrypt(Pkcs1v15Encrypt, data);
    // ruleid: enqrypta.crypto.rust.rsa-encrypt
    let c = openssl_key.private_decrypt(data, &mut buf, Padding::PKCS1_OAEP);
    // ok: enqrypta.crypto.rust.rsa-encrypt
    let d = key.sign(Pkcs1v15Sign::new_unprefixed(), data);
    // ruleid: enqrypta.crypto.rust.rsa-sign
    let e = Pkcs1v15Sign::new::<Sha256>();
    // ruleid: enqrypta.crypto.rust.rsa-sign
    let f = RsaKeyPair::from_pkcs8(&pkcs8);
    // ok: enqrypta.crypto.rust.rsa-sign
    let g = RsaPublicKey::new(n, e);
}

fn curves(rng: &mut OsRng, seed: &[u8; 32]) {
    // ruleid: enqrypta.crypto.rust.ecdsa
    let a = p256::ecdsa::SigningKey::random(rng);
    // ruleid: enqrypta.crypto.rust.ecdsa
    let b = SigningKey::random(rng);
    // ruleid: enqrypta.crypto.rust.ecdsa
    let c = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rand);
    // ok: enqrypta.crypto.rust.ecdsa
    let d = k256::ecdsa::SigningKey::random(rng);
    // ruleid: enqrypta.crypto.rust.ecdh
    let e = EphemeralSecret::random(rng);
    // ruleid: enqrypta.crypto.rust.ecdh
    let f = EphemeralPrivateKey::generate(&agreement::ECDH_P384, &rand);
    // ok: enqrypta.crypto.rust.ecdh
    let g = p256::PublicKey::from_sec1_bytes(seed);
    // ruleid: enqrypta.crypto.rust.x25519
    let h = StaticSecret::random_from_rng(rng);
    // ruleid: enqrypta.crypto.rust.x25519
    let i = EphemeralPrivateKey::generate(&agreement::X25519, &rand);
    // ok: enqrypta.crypto.rust.x25519
    let j = x25519_dalek::PublicKey::from(seed.clone());
    // ruleid: enqrypta.crypto.rust.ed25519
    let k = ed25519_dalek::SigningKey::generate(rng);
    // ruleid: enqrypta.crypto.rust.ed25519
    let l = Ed25519KeyPair::generate_pkcs8(&rand);
    // ok: enqrypta.crypto.rust.ed25519
    let m = ed25519_dalek::VerifyingKey::from_bytes(seed);
}

fn symmetric(key: &[u8]) {
    // ruleid: enqrypta.crypto.rust.aes
    let a = Aes256Gcm::new_from_slice(key);
    // ruleid: enqrypta.crypto.rust.aes
    let b = Cipher::aes_128_cbc();
    // ruleid: enqrypta.crypto.rust.aes
    let c = UnboundKey::new(&aead::AES_256_GCM, key);
    // ok: enqrypta.crypto.rust.aes
    let d = ChaCha20Poly1305::new_from_slice(key);
    // ok: enqrypta.crypto.rust.aes
    let e = Cipher::chacha20_poly1305();
}

fn digests(data: &[u8]) {
    // ruleid: enqrypta.crypto.rust.sha1
    let a = Sha1::digest(data);
    // ruleid: enqrypta.crypto.rust.sha1
    let b = MessageDigest::sha1();
    // ok: enqrypta.crypto.rust.sha1
    let c = Sha256::digest(data);
    // ruleid: enqrypta.crypto.rust.md5
    let d = md5::compute(data);
    // ruleid: enqrypta.crypto.rust.md5
    let e = Md5::new();
    // ok: enqrypta.crypto.rust.md5
    let f = MessageDigest::sha256();
}

fn post_quantum(rng: &mut OsRng) {
    // ruleid: enqrypta.crypto.rust.ml-kem
    let a = MlKem768::generate(rng);
    // ok: enqrypta.crypto.rust.ml-kem
    let b = X25519Kyber768::generate(rng);
    // ruleid: enqrypta.crypto.rust.ml-dsa
    let c = MlDsa65::key_gen(rng);
    // ok: enqrypta.crypto.rust.ml-dsa
    let d = SlhDsaSha2_128s::key_gen(rng);
}
