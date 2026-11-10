fn weak_ciphers(key: &[u8]) {
    // ruleid: enqrypta.misuse.rust.weak-cipher-3des
    let a = Cipher::des_ede3_cbc();
    // ruleid: enqrypta.misuse.rust.weak-cipher-3des
    let b = des::TdesEde3::new_from_slice(key);
    // ok: enqrypta.misuse.rust.weak-cipher-3des
    let c = Cipher::aes_256_gcm();
    // ruleid: enqrypta.misuse.rust.weak-cipher-des
    let d = Cipher::des_cbc();
    // ok: enqrypta.misuse.rust.weak-cipher-des
    let e = Cipher::aes_128_cbc();
    // ruleid: enqrypta.misuse.rust.weak-cipher-rc4
    let f = Cipher::rc4();
    // ok: enqrypta.misuse.rust.weak-cipher-rc4
    let g = Cipher::chacha20();
    // ruleid: enqrypta.misuse.rust.weak-cipher-blowfish
    let h = Cipher::bf_cbc();
    // ok: enqrypta.misuse.rust.weak-cipher-blowfish
    let i = Cipher::camellia_256_cbc();
}

fn modes(key: &[u8]) {
    // ruleid: enqrypta.misuse.rust.ecb-mode
    let a = Cipher::aes_128_ecb();
    // ruleid: enqrypta.misuse.rust.ecb-mode
    let b = ecb::Encryptor::<aes::Aes128>::new(key.into());
    // ok: enqrypta.misuse.rust.ecb-mode
    let c = cbc::Encryptor::<aes::Aes128>::new(key.into(), iv.into());
}

fn weak_hashes(pkey: &PKey<Private>, key: &[u8]) {
    // ruleid: enqrypta.misuse.rust.sha1-signature
    let a = Signer::new(MessageDigest::sha1(), pkey);
    // ruleid: enqrypta.misuse.rust.sha1-signature
    let b = Pkcs1v15Sign::new::<Sha1>();
    // ok: enqrypta.misuse.rust.sha1-signature
    let c = Signer::new(MessageDigest::sha256(), pkey);
    // ruleid: enqrypta.misuse.rust.md5-signature-or-mac
    let d = Hmac::<Md5>::new_from_slice(key);
    // ok: enqrypta.misuse.rust.md5-signature-or-mac
    let e = Hmac::<Sha256>::new_from_slice(key);
}

fn seeded_keys() {
    let mut rng = StdRng::seed_from_u64(42);
    // ruleid: enqrypta.misuse.rust.insecure-random
    let a = RsaPrivateKey::new(&mut rng, 2048);
    // ruleid: enqrypta.misuse.rust.insecure-random
    let b = SigningKey::random(&mut rng);
    let mut os = OsRng;
    // ok: enqrypta.misuse.rust.insecure-random
    let c = SigningKey::random(&mut os);
}

fn fixed_nonces(cipher: &Aes256Gcm, key: &[u8], data: &[u8], nonce: &[u8]) {
    // ruleid: enqrypta.misuse.rust.hardcoded-iv
    let a = Nonce::from_slice(b"unique nonce");
    // ruleid: enqrypta.misuse.rust.hardcoded-iv
    let b = Nonce::from_slice(&[0u8; 12]);
    // ruleid: enqrypta.misuse.rust.hardcoded-iv
    let c = encrypt(Cipher::aes_256_cbc(), key, Some(b"0123456789abcdef"), data);
    // ok: enqrypta.misuse.rust.hardcoded-iv
    let d = Nonce::from_slice(nonce);
    // ruleid: enqrypta.misuse.rust.hardcoded-key
    let e = Key::<Aes256Gcm>::from_slice(b"an example very very secret key.");
    // ruleid: enqrypta.misuse.rust.hardcoded-key
    let f = Aes128Gcm::new_from_slice(b"0123456789abcdef");
    // ruleid: enqrypta.misuse.rust.hardcoded-key
    let g = Hmac::<Sha256>::new_from_slice(b"webhook-secret");
    // ok: enqrypta.misuse.rust.hardcoded-key
    let h = Aes128Gcm::new_from_slice(key);
}

fn tls(builder: ClientBuilder, ctx: &mut SslContextBuilder, config: ClientConfig) {
    // ruleid: enqrypta.misuse.rust.tls-verify-disabled
    let a = builder.danger_accept_invalid_certs(true);
    // ruleid: enqrypta.misuse.rust.tls-verify-disabled
    ctx.set_verify(SslVerifyMode::NONE);
    // ruleid: enqrypta.misuse.rust.tls-verify-disabled
    let b = config.dangerous().set_certificate_verifier(Arc::new(NoVerifier));
    // ok: enqrypta.misuse.rust.tls-verify-disabled
    ctx.set_verify(SslVerifyMode::PEER);
    // ruleid: enqrypta.misuse.rust.weak-tls-version
    ctx.set_min_proto_version(Some(SslVersion::TLS1));
    // ruleid: enqrypta.misuse.rust.weak-tls-version
    let c = TlsConnector::builder().min_protocol_version(Some(Protocol::Tlsv11));
    // ok: enqrypta.misuse.rust.weak-tls-version
    ctx.set_min_proto_version(Some(SslVersion::TLS1_2));
}
