<?php

namespace App\Crypto;

use Defuse\Crypto\Crypto;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Crypt;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Rsa\Sha512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HmacSha256;
use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
// ruleid: enqrypta.crypto.php.passport-oauth-keys
use Laravel\Passport\HasApiTokens;
// ok: enqrypta.crypto.php.passport-oauth-keys
use Laravel\Sanctum\HasApiTokens as SanctumTokens;

class Keys
{
    const KEY_TYPE = OPENSSL_KEYTYPE_RSA;
    const CIPHER = 'aes-128-cbc';

    public function rsaKeys(int $bits)
    {
        // ruleid: enqrypta.crypto.php.rsa-keygen
        openssl_pkey_new();
        // ruleid: enqrypta.crypto.php.rsa-keygen
        openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        // ruleid: enqrypta.crypto.php.rsa-keygen
        \openssl_pkey_new(array("private_key_type" => \OPENSSL_KEYTYPE_RSA));
        // ruleid: enqrypta.crypto.php.rsa-keygen
        OPENSSL_PKEY_NEW(['digest_alg' => 'sha512', 'private_key_bits' => 4096]);
        $config = ['digest_alg' => 'sha256', 'private_key_bits' => 3072, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
        // ruleid: enqrypta.crypto.php.rsa-keygen
        $res = openssl_pkey_new($config);
        $defaults = ['private_key_bits' => $bits];
        // ruleid: enqrypta.crypto.php.rsa-keygen
        openssl_pkey_new($defaults);
        // ruleid: enqrypta.crypto.php.rsa-keygen
        RSA::createKey(3072);
        // ruleid: enqrypta.crypto.php.rsa-keygen
        \phpseclib3\Crypt\RSA::createKey();
        $legacy = new \phpseclib\Crypt\RSA();
        // ruleid: enqrypta.crypto.php.rsa-keygen
        $legacy->createKey(2048);
        // ok: enqrypta.crypto.php.rsa-keygen
        openssl_pkey_get_private($pem);
        // ok: enqrypta.crypto.php.rsa-keygen
        $other->createKey(2048);
        // ok: enqrypta.crypto.php.rsa-keygen
        DSA::createKey(2048);
    }

    public function rsaUse($data, $pub, $priv)
    {
        // ruleid: enqrypta.crypto.php.rsa-encrypt
        openssl_public_encrypt($data, $encrypted, $pub, OPENSSL_PKCS1_OAEP_PADDING);
        // ruleid: enqrypta.crypto.php.rsa-encrypt
        \openssl_private_decrypt($data, $plain, $priv, \OPENSSL_PKCS1_OAEP_PADDING);
        // ruleid: enqrypta.crypto.php.rsa-encrypt
        openssl_public_encrypt(data: $data, encrypted_data: $out, public_key: $pub, padding: OPENSSL_PKCS1_OAEP_PADDING);
        // ruleid: enqrypta.crypto.php.rsa-encrypt
        $key->withPadding(RSA::ENCRYPTION_OAEP);
        // ok: enqrypta.crypto.php.rsa-encrypt
        openssl_pkey_get_public($pub);
        // ruleid: enqrypta.crypto.php.rsa-sign
        openssl_private_encrypt($digest, $signature, $priv);
        // ruleid: enqrypta.crypto.php.rsa-sign
        openssl_public_decrypt($signature, $digest, $pub);
        // ruleid: enqrypta.crypto.php.rsa-sign
        $key->withPadding(RSA::SIGNATURE_PSS);
        // ok: enqrypta.crypto.php.rsa-sign
        $key->withHash('sha256');
        // ruleid: enqrypta.crypto.php.openssl-sign
        openssl_sign($data, $signature, $priv, OPENSSL_ALGO_SHA256);
        // ruleid: enqrypta.crypto.php.openssl-sign
        openssl_verify($data, $signature, $pub, 'sha384');
        // ruleid: enqrypta.crypto.php.openssl-sign
        openssl_pkcs7_sign($in, $out, $cert, $priv, $headers);
        // ruleid: enqrypta.crypto.php.openssl-sign
        openssl_csr_sign($csr, null, $priv, 365, ['digest_alg' => 'sha256']);
        // ok: enqrypta.crypto.php.openssl-sign
        openssl_x509_read($cert);
        // ruleid: enqrypta.crypto.php.openssl-seal
        openssl_seal($data, $sealed, $keys, [$pub], 'aes-256-cbc', $iv);
        // ruleid: enqrypta.crypto.php.openssl-seal
        openssl_open($sealed, $plain, $envKey, $priv, 'aes-256-cbc', $iv);
        // ok: enqrypta.crypto.php.openssl-seal
        $seal->open();
        // ruleid: enqrypta.crypto.php.pkcs7-cms-encrypt
        openssl_pkcs7_encrypt($in, $out, $cert, $headers, 0, OPENSSL_CIPHER_AES_256_CBC);
        // ruleid: enqrypta.crypto.php.pkcs7-cms-encrypt
        openssl_cms_decrypt($in, $out, $cert, $priv);
        // ok: enqrypta.crypto.php.pkcs7-cms-encrypt
        openssl_pkcs7_read($in, $certs);
    }

    public function tokens($payload, $key, $jwt)
    {
        // ruleid: enqrypta.crypto.php.jwt-rsa
        JWT::encode($payload, $key, 'RS256');
        // ruleid: enqrypta.crypto.php.jwt-rsa
        JWT::decode($jwt, new Key($key, 'PS384'));
        // ruleid: enqrypta.crypto.php.jwt-rsa
        new \Lcobucci\JWT\Signer\Rsa\Sha256();
        // ruleid: enqrypta.crypto.php.jwt-rsa
        new Sha512();
        // ruleid: enqrypta.crypto.php.jwt-rsa
        new \Jose\Component\Signature\Algorithm\RS256();
        // ok: enqrypta.crypto.php.jwt-rsa
        JWT::encode($payload, $key, 'HS256');
        // ok: enqrypta.crypto.php.jwt-rsa
        new HmacSha256();
        // ruleid: enqrypta.crypto.php.jwt-ecdsa
        JWT::encode($payload, $key, 'ES256');
        // ruleid: enqrypta.crypto.php.jwt-ecdsa
        Configuration::forAsymmetricSigner(new \Lcobucci\JWT\Signer\Ecdsa\Sha384(), $priv, $pub);
        // ruleid: enqrypta.crypto.php.jwt-ecdsa
        new ES512();
        // ok: enqrypta.crypto.php.jwt-ecdsa
        JWT::encode($payload, $key, 'HS512');
        // ruleid: enqrypta.crypto.php.jwt-eddsa
        JWT::encode($payload, $key, 'EdDSA');
        // ruleid: enqrypta.crypto.php.jwt-eddsa
        new \Lcobucci\JWT\Signer\Eddsa();
        // ok: enqrypta.crypto.php.jwt-eddsa
        JWT::encode($payload, $key, 'HS384');
        // ruleid: enqrypta.crypto.php.passport-oauth-keys
        Passport::loadKeysFrom(__DIR__ . '/../secrets/oauth');
        // ruleid: enqrypta.crypto.php.passport-oauth-keys
        new \League\OAuth2\Server\CryptKey($path, null, false);
        // ok: enqrypta.crypto.php.passport-oauth-keys
        Passport::tokensExpireIn(now()->addDays(15));
    }

    public function curves($peer, $priv, $curve)
    {
        // ruleid: enqrypta.crypto.php.ec-keygen
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        // ruleid: enqrypta.crypto.php.ec-keygen
        openssl_pkey_new(['curve_name' => 'secp384r1']);
        // ruleid: enqrypta.crypto.php.ec-keygen
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC]);
        $ecConfig = ['curve_name' => 'secp521r1', 'private_key_type' => OPENSSL_KEYTYPE_EC];
        // ruleid: enqrypta.crypto.php.ec-keygen
        openssl_pkey_new($ecConfig);
        // ruleid: enqrypta.crypto.php.ec-keygen
        EC::createKey('secp256r1');
        // ok: enqrypta.crypto.php.ec-keygen
        openssl_get_curve_names();
        // ruleid: enqrypta.crypto.php.ecdh
        openssl_pkey_derive($peer, $priv);
        // ok: enqrypta.crypto.php.ecdh
        openssl_pkey_export($priv, $pem);
        // ruleid: enqrypta.crypto.php.dh
        openssl_dh_compute_key($peerPublic, $priv);
        // ruleid: enqrypta.crypto.php.dh
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_DH, 'dh' => ['p' => $p, 'g' => $g]]);
        // ok: enqrypta.crypto.php.dh
        openssl_pkey_get_details($priv);
        // ruleid: enqrypta.crypto.php.x25519
        $kp = sodium_crypto_box_keypair();
        // ruleid: enqrypta.crypto.php.x25519
        sodium_crypto_kx_client_session_keys($clientKp, $serverPk);
        // ruleid: enqrypta.crypto.php.x25519
        \sodium_crypto_box_seal($msg, $pk);
        // ruleid: enqrypta.crypto.php.x25519
        EC::createKey('Curve25519');
        // ok: enqrypta.crypto.php.x25519
        sodium_crypto_secretbox($msg, $nonce, $key);
        // ruleid: enqrypta.crypto.php.ed25519
        sodium_crypto_sign_keypair();
        // ruleid: enqrypta.crypto.php.ed25519
        sodium_crypto_sign_detached($msg, $sk);
        // ruleid: enqrypta.crypto.php.ed25519
        EC::createKey('Ed25519');
        // ok: enqrypta.crypto.php.ed25519
        sodium_crypto_generichash($msg);
    }

    public function symmetric($data, $key, $iv)
    {
        // ruleid: enqrypta.crypto.php.aes
        openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        // ruleid: enqrypta.crypto.php.aes
        OPENSSL_DECRYPT($data, 'AES-128-CBC', $key, 0, $iv);
        // ruleid: enqrypta.crypto.php.aes
        openssl_encrypt(data: $data, cipher_algo: 'aes-192-ctr', passphrase: $key, iv: $iv);
        $cipher = 'aes-256-cbc';
        // ruleid: enqrypta.crypto.php.aes
        \openssl_encrypt($data, $cipher, $key, 0, $iv);
        // ruleid: enqrypta.crypto.php.aes
        openssl_decrypt($data, self::CIPHER, $key, 0, $iv);
        // ok: enqrypta.crypto.php.aes
        openssl_encrypt($data, 'chacha20-poly1305', $key, 0, $iv);
        // ruleid: enqrypta.crypto.php.aes-gcm-sodium
        sodium_crypto_aead_aes256gcm_encrypt($data, $ad, $nonce, $key);
        // ok: enqrypta.crypto.php.aes-gcm-sodium
        sodium_crypto_aead_aes256gcm_is_available();
        // ruleid: enqrypta.crypto.php.aes-phpseclib
        new AES('gcm');
        // ruleid: enqrypta.crypto.php.aes-phpseclib
        new \phpseclib\Crypt\AES(\phpseclib\Crypt\Base::MODE_CBC);
        // ok: enqrypta.crypto.php.aes-phpseclib
        new AESCipherConfig('gcm');
        // ruleid: enqrypta.crypto.php.laravel-encrypter
        Crypt::encryptString($data);
        // ruleid: enqrypta.crypto.php.laravel-encrypter
        \Illuminate\Support\Facades\Crypt::decrypt($data);
        // ruleid: enqrypta.crypto.php.laravel-encrypter
        encrypt($data);
        // ok: enqrypta.crypto.php.laravel-encrypter
        $this->encrypt($data);
        // ruleid: enqrypta.crypto.php.laravel-cipher-config
        new Encrypter($key, 'AES-256-GCM');
        // ok: enqrypta.crypto.php.laravel-cipher-config
        new Encrypter($key, $configuredCipher);
        // ruleid: enqrypta.crypto.php.defuse-encryption
        Crypto::encrypt($data, $key);
        // ruleid: enqrypta.crypto.php.defuse-encryption
        Crypto::decryptWithPassword($data, $password);
        // ok: enqrypta.crypto.php.defuse-encryption
        Crypto::legacyDecrypt($data, $key);
    }

    public function hashes($data, $path, $values)
    {
        // ruleid: enqrypta.crypto.php.sha1
        sha1($data);
        // ruleid: enqrypta.crypto.php.sha1
        \SHA1_FILE($path);
        // ruleid: enqrypta.crypto.php.sha1
        hash('sha1', $data);
        // ruleid: enqrypta.crypto.php.sha1
        hash_init('SHA1');
        // ruleid: enqrypta.crypto.php.sha1
        openssl_digest($data, 'sha1');
        // ruleid: enqrypta.crypto.php.sha1
        array_map('sha1', $values);
        // ruleid: enqrypta.crypto.php.sha1
        mhash(MHASH_SHA1, $data);
        // ok: enqrypta.crypto.php.sha1
        hash('sha256', $data);
        // ok: enqrypta.crypto.php.sha1
        hash_hmac('sha1', $data, $secret);
        // ruleid: enqrypta.crypto.php.md5
        md5($data);
        // ruleid: enqrypta.crypto.php.md5
        MD5($data);
        // ruleid: enqrypta.crypto.php.md5
        \md5_file($path);
        // ruleid: enqrypta.crypto.php.md5
        hash(algo: 'md5', data: $data);
        // ruleid: enqrypta.crypto.php.md5
        hash_file('md5', $path);
        // ruleid: enqrypta.crypto.php.md5
        call_user_func('md5', $data);
        // ok: enqrypta.crypto.php.md5
        hash('xxh3', $data);
        // ok: enqrypta.crypto.php.md5
        $this->md5($data);
    }
}

function app_config()
{
    // ruleid: enqrypta.crypto.php.laravel-cipher-config
    return ['name' => 'App', 'cipher' => 'AES-256-CBC', 'key' => env('APP_KEY')];
}

function other_config()
{
    // ok: enqrypta.crypto.php.laravel-cipher-config
    return ['name' => 'App', 'cipher' => env('APP_CIPHER')];
}

class Account extends Model
{
    // ruleid: enqrypta.crypto.php.laravel-encrypter
    protected $casts = ['created_at' => 'datetime', 'secret' => 'encrypted', 'meta' => 'encrypted:array'];
}

class Profile extends Model
{
    // ok: enqrypta.crypto.php.laravel-encrypter
    protected $casts = ['status' => 'string', 'flags' => 'array'];

    protected function casts(): array
    {
        // ruleid: enqrypta.crypto.php.laravel-encrypter
        return ['options' => \Illuminate\Database\Eloquent\Casts\AsEncryptedArrayObject::class];
    }
}

class RandomSources
{
    public function tokens($kms)
    {
        // ruleid: enqrypta.crypto.php.csprng
        $sessionToken = bin2hex(random_bytes(32));
        // ruleid: enqrypta.crypto.php.csprng
        $otp = \random_int(0, 999999);
        // ok: enqrypta.crypto.php.csprng
        $jitter = mt_rand();
        // ruleid: enqrypta.crypto.php.csprng-openssl
        $nonce = openssl_random_pseudo_bytes(12);
        // ok: enqrypta.crypto.php.csprng-openssl
        $ivLength = openssl_cipher_iv_length('aes-256-gcm');
        // ruleid: enqrypta.crypto.php.aws-kms-generate-random
        $apiKey = $kms->generateRandom(['NumberOfBytes' => 32])['Plaintext'];
        // ok: enqrypta.crypto.php.aws-kms-generate-random
        $kms->listKeys([]);
        return [$sessionToken, $otp, $jitter, $nonce, $ivLength, $apiKey];
    }
}

