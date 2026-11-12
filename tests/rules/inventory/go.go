package inventory

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const keyBits = 3072

func rsaUse(bits int, pub *rsa.PublicKey, priv *rsa.PrivateKey, msg, digest []byte) {
	// ruleid: enqrypta.crypto.go.rsa-keygen
	rsa.GenerateKey(rand.Reader, 2048)
	// ruleid: enqrypta.crypto.go.rsa-keygen
	rsa.GenerateKey(rand.Reader, keyBits)
	// ruleid: enqrypta.crypto.go.rsa-keygen
	rsa.GenerateKey(rand.Reader, bits)
	// ok: enqrypta.crypto.go.rsa-keygen
	rsa.GenerateMultiPrimeKey
	// ruleid: enqrypta.crypto.go.rsa-encrypt-oaep
	rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
	// ok: enqrypta.crypto.go.rsa-encrypt-oaep
	pub.Size()
	// ruleid: enqrypta.crypto.go.rsa-encrypt-pkcs1v15
	rsa.DecryptPKCS1v15(rand.Reader, priv, msg)
	// ok: enqrypta.crypto.go.rsa-encrypt-pkcs1v15
	priv.Precompute()
	// ruleid: enqrypta.crypto.go.rsa-sign
	rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest, nil)
	// ruleid: enqrypta.crypto.go.rsa-sign
	rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, msg)
	// ok: enqrypta.crypto.go.rsa-sign
	ed25519.Verify(nil, msg, digest)
}

func ecUse(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, digest, sig []byte) {
	// ruleid: enqrypta.crypto.go.ecdsa-keygen
	ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	// ok: enqrypta.crypto.go.ecdsa-keygen
	priv.ECDH()
	// ruleid: enqrypta.crypto.go.ecdsa-sign
	ecdsa.SignASN1(rand.Reader, priv, digest)
	// ruleid: enqrypta.crypto.go.ecdsa-sign
	ecdsa.VerifyASN1(pub, digest, sig)
	// ok: enqrypta.crypto.go.ecdsa-sign
	priv.Public()
	// ruleid: enqrypta.crypto.go.ecdh
	ecdh.P256().GenerateKey(rand.Reader)
	// ruleid: enqrypta.crypto.go.ecdh
	ecdh.P521().NewPrivateKey(digest)
	// ok: enqrypta.crypto.go.ecdh
	ecdh.P256().NewPublicKey(digest)
}

func curves(seed, scalar, point []byte) {
	// ruleid: enqrypta.crypto.go.x25519
	ecdh.X25519().GenerateKey(rand.Reader)
	// ruleid: enqrypta.crypto.go.x25519
	curve25519.X25519(scalar, point)
	// ok: enqrypta.crypto.go.x25519
	ecdh.X25519().NewPublicKey(point)
	// ruleid: enqrypta.crypto.go.ed25519
	ed25519.GenerateKey(rand.Reader)
	// ruleid: enqrypta.crypto.go.ed25519
	ed25519.NewKeyFromSeed(seed)
	// ok: enqrypta.crypto.go.ed25519
	ed25519.Verify(nil, seed, scalar)
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	// ruleid: enqrypta.crypto.go.aes-gcm
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func aesCTR(key, iv []byte) cipher.Stream {
	// ruleid: enqrypta.crypto.go.aes
	block, _ := aes.NewCipher(key)
	return cipher.NewCTR(block, iv)
}

func notAES(key []byte) {
	// ok: enqrypta.crypto.go.aes
	chacha20poly1305.New(key)
	// ok: enqrypta.crypto.go.aes-gcm
	chacha20poly1305.NewX(key)
}

func digests(data []byte) {
	// ruleid: enqrypta.crypto.go.sha1
	sha1.Sum(data)
	// ruleid: enqrypta.crypto.go.sha1
	sha1.New()
	// ok: enqrypta.crypto.go.sha1
	sha256.Sum256(data)
	// ruleid: enqrypta.crypto.go.md5
	md5.Sum(data)
	// ok: enqrypta.crypto.go.md5
	sha256.New()
}

func postQuantum(seed []byte) {
	// ruleid: enqrypta.crypto.go.ml-kem-768
	mlkem.GenerateKey768()
	// ok: enqrypta.crypto.go.ml-kem-768
	mlkem.SharedKeySize()
	// ruleid: enqrypta.crypto.go.ml-kem-1024
	mlkem.NewDecapsulationKey1024(seed)
	// ok: enqrypta.crypto.go.ml-kem-1024
	mlkem.SeedSize()
	// ruleid: enqrypta.crypto.go.ml-dsa
	mldsa65.GenerateKey(rand.Reader)
	// ok: enqrypta.crypto.go.ml-dsa
	mldsa65.Scheme()
}
