package misuse

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"math/rand"

	"golang.org/x/crypto/blowfish"
)

func weakCiphers(key []byte) {
	// ruleid: enqrypta.misuse.go.weak-cipher-3des
	des.NewTripleDESCipher(key)
	// ok: enqrypta.misuse.go.weak-cipher-3des
	aes.NewCipher(key)
	// ruleid: enqrypta.misuse.go.weak-cipher-des
	des.NewCipher(key)
	// ok: enqrypta.misuse.go.weak-cipher-des
	aes.NewCipher(key)
	// ruleid: enqrypta.misuse.go.weak-cipher-rc4
	rc4.NewCipher(key)
	// ok: enqrypta.misuse.go.weak-cipher-rc4
	aes.NewCipher(key)
	// ruleid: enqrypta.misuse.go.weak-cipher-blowfish
	blowfish.NewCipher(key)
	// ok: enqrypta.misuse.go.weak-cipher-blowfish
	aes.NewCipher(key)
}

func weakHashes(random io.Reader, priv *rsa.PrivateKey, key, digest []byte) {
	// ruleid: enqrypta.misuse.go.sha1-signature
	rsa.SignPKCS1v15(random, priv, crypto.SHA1, digest)
	// ok: enqrypta.misuse.go.sha1-signature
	rsa.SignPKCS1v15(random, priv, crypto.SHA256, digest)
	// ruleid: enqrypta.misuse.go.md5-signature-or-mac
	hmac.New(md5.New, key)
	// ruleid: enqrypta.misuse.go.md5-signature-or-mac
	rsa.SignPKCS1v15(random, priv, crypto.MD5, digest)
	// ok: enqrypta.misuse.go.md5-signature-or-mac
	hmac.New(sha256.New, key)
}

func fixedIVs(block cipher.Block, aead cipher.AEAD, iv, nonce, plaintext []byte) {
	// ruleid: enqrypta.misuse.go.hardcoded-iv
	cipher.NewCBCEncrypter(block, []byte("1234567890123456"))
	// ruleid: enqrypta.misuse.go.hardcoded-iv
	cipher.NewCTR(block, make([]byte, 16))
	// ruleid: enqrypta.misuse.go.hardcoded-iv
	aead.Seal(nil, []byte("fixed-nonce!"), plaintext, nil)
	// ok: enqrypta.misuse.go.hardcoded-iv
	cipher.NewCBCEncrypter(block, iv)
	// ok: enqrypta.misuse.go.hardcoded-iv
	aead.Seal(nil, nonce, plaintext, nil)
}

func fixedKeys(key []byte) {
	// ruleid: enqrypta.misuse.go.hardcoded-key
	aes.NewCipher([]byte("0123456789abcdef"))
	// ruleid: enqrypta.misuse.go.hardcoded-key
	hmac.New(sha256.New, []byte("webhook-secret"))
	// ok: enqrypta.misuse.go.hardcoded-key
	aes.NewCipher(key)
}

func tlsConfigs(cfg *tls.Config) {
	// ruleid: enqrypta.misuse.go.tls-verify-disabled
	_ = &tls.Config{InsecureSkipVerify: true}
	// ruleid: enqrypta.misuse.go.tls-verify-disabled
	cfg.InsecureSkipVerify = true
	// ok: enqrypta.misuse.go.tls-verify-disabled
	_ = &tls.Config{InsecureSkipVerify: false}
	// ruleid: enqrypta.misuse.go.weak-tls-version
	_ = &tls.Config{MinVersion: tls.VersionTLS10}
	// ruleid: enqrypta.misuse.go.weak-tls-version
	cfg.MinVersion = tls.VersionTLS11
	// ok: enqrypta.misuse.go.weak-tls-version
	_ = &tls.Config{MinVersion: tls.VersionTLS12}
}

func randomness(n int) {
	sessionKey := make([]byte, 32)
	// ruleid: enqrypta.misuse.go.insecure-random
	rand.Read(sessionKey)
	// ruleid: enqrypta.misuse.go.insecure-random
	resetToken := rand.Int63()
	// ok: enqrypta.misuse.go.insecure-random
	jitter := rand.Intn(n)
	_, _ = resetToken, jitter
}
