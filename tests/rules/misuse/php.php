<?php

namespace App\Legacy;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Http;
use Lcobucci\JWT\Configuration;
use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\TripleDES;

class Ciphers
{
    const LEGACY = 'des-cbc';

    public function weak($data, $key, $iv)
    {
        // ruleid: enqrypta.misuse.php.weak-cipher-3des
        openssl_encrypt($data, 'des-ede3-cbc', $key, 0, $iv);
        // ruleid: enqrypta.misuse.php.weak-cipher-3des
        openssl_decrypt(data: $data, cipher_algo: 'DES-EDE3', passphrase: $key);
        // ruleid: enqrypta.misuse.php.weak-cipher-3des, enqrypta.misuse.php.mcrypt-use
        mcrypt_encrypt(MCRYPT_3DES, $key, $data, MCRYPT_MODE_CBC, $iv);
        // ruleid: enqrypta.misuse.php.weak-cipher-3des
        new TripleDES('cbc');
        // ok: enqrypta.misuse.php.weak-cipher-3des
        openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);
        // ruleid: enqrypta.misuse.php.weak-cipher-des
        openssl_encrypt($data, self::LEGACY, $key, 0, $iv);
        // ruleid: enqrypta.misuse.php.weak-cipher-des
        \openssl_decrypt($data, 'des', $key);
        // ruleid: enqrypta.misuse.php.weak-cipher-des, enqrypta.misuse.php.mcrypt-use
        mcrypt_decrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_CBC, $iv);
        // ruleid: enqrypta.misuse.php.weak-cipher-des
        openssl_seal($data, $sealed, $keys, [$pub], 'des-cbc', $iv);
        // ruleid: enqrypta.misuse.php.weak-cipher-3des
        openssl_encrypt($data, 'des-ede3-cfb', $key, 0, $iv);
        // ok: enqrypta.misuse.php.weak-cipher-des
        openssl_encrypt($data, 'desx-cbc-like-but-not', $key, 0, $iv);
        $stream = 'rc4';
        // ruleid: enqrypta.misuse.php.weak-cipher-rc4
        openssl_encrypt($data, $stream, $key);
        // ruleid: enqrypta.misuse.php.weak-cipher-rc4, enqrypta.misuse.php.mcrypt-use
        mcrypt_module_open('arcfour', '', 'stream', '');
        // ok: enqrypta.misuse.php.weak-cipher-rc4
        openssl_encrypt($data, 'chacha20', $key, 0, $iv);
        // ruleid: enqrypta.misuse.php.weak-cipher-blowfish
        OPENSSL_ENCRYPT($data, 'bf-cbc', $key, 0, $iv);
        // ruleid: enqrypta.misuse.php.weak-cipher-blowfish, enqrypta.misuse.php.mcrypt-use
        mcrypt_get_iv_size(MCRYPT_BLOWFISH, MCRYPT_MODE_CBC);
        // ok: enqrypta.misuse.php.weak-cipher-blowfish
        password_hash($data, PASSWORD_BCRYPT);
        // ruleid: enqrypta.misuse.php.ecb-mode
        openssl_encrypt($data, 'aes-128-ecb', $key);
        // ruleid: enqrypta.misuse.php.ecb-mode
        new AES('ecb');
        // ruleid: enqrypta.misuse.php.ecb-mode, enqrypta.misuse.php.mcrypt-use
        mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, 'ecb');
        // ruleid: enqrypta.misuse.php.ecb-mode
        new \phpseclib\Crypt\AES(\phpseclib\Crypt\Base::MODE_ECB);
        // ok: enqrypta.misuse.php.ecb-mode
        openssl_encrypt($data, 'aes-128-cbc', $key, 0, $iv);
        // ok: enqrypta.misuse.php.mcrypt-use
        openssl_cipher_iv_length('aes-256-gcm');
    }

    public function signatures($data, $priv, $pub, $secret)
    {
        // ruleid: enqrypta.misuse.php.sha1-signature
        openssl_sign($data, $signature, $priv, OPENSSL_ALGO_SHA1);
        // ruleid: enqrypta.misuse.php.sha1-signature
        openssl_verify($data, $signature, $pub, 'sha1WithRSAEncryption');
        // ruleid: enqrypta.misuse.php.sha1-signature
        openssl_sign($data, $signature, $priv);
        // ruleid: enqrypta.misuse.php.sha1-signature
        openssl_csr_new($dn, $priv, ['digest_alg' => 'sha1']);
        // ruleid: enqrypta.misuse.php.sha1-signature
        $key->withHash('sha1');
        // ok: enqrypta.misuse.php.sha1-signature
        openssl_sign($data, $signature, $priv, OPENSSL_ALGO_SHA256);
        // ok: enqrypta.misuse.php.sha1-signature
        openssl_sign(data: $data, signature: $signature, private_key: $priv, algorithm: OPENSSL_ALGO_SHA512);
        // ruleid: enqrypta.misuse.php.md5-signature-or-mac
        openssl_sign($data, $signature, $priv, \OPENSSL_ALGO_MD5);
        // ruleid: enqrypta.misuse.php.md5-signature-or-mac
        hash_hmac('md5', $data, $secret);
        // ruleid: enqrypta.misuse.php.md5-signature-or-mac
        hash_init('md5', HASH_HMAC, $secret);
        // ruleid: enqrypta.misuse.php.md5-signature-or-mac
        mhash(MHASH_MD5, $data, $secret);
        // ruleid: enqrypta.misuse.php.md5-signature-or-mac
        openssl_csr_sign($csr, null, $priv, 365, ['digest_alg' => 'md5']);
        // ok: enqrypta.misuse.php.md5-signature-or-mac
        hash_hmac('sha256', $data, $secret);
        // ok: enqrypta.misuse.php.md5-signature-or-mac
        hash_init('md5');
    }

    public function randomness($user)
    {
        // ruleid: enqrypta.misuse.php.insecure-random
        $token = md5(mt_rand());
        // ruleid: enqrypta.misuse.php.insecure-random
        $this->resetToken = sha1(uniqid('', true));
        // ruleid: enqrypta.misuse.php.insecure-random
        $api_key = str_shuffle('abcdefghijklmnopqrstuvwxyz0123456789');
        // ruleid: enqrypta.misuse.php.insecure-random
        $payload = ['csrf_token' => \rand(100000, 999999)];
        // ok: enqrypta.misuse.php.insecure-random
        $token = bin2hex(random_bytes(32));
        // ok: enqrypta.misuse.php.insecure-random
        $cache_key = 'user:' . mt_rand();
        // ok: enqrypta.misuse.php.insecure-random
        $index = mt_rand(0, 10);
    }

    public function generateApiToken()
    {
        // ruleid: enqrypta.misuse.php.insecure-random
        return substr(md5(rand()), 0, 16);
    }

    public function constants($data, $key, $msg)
    {
        // ruleid: enqrypta.misuse.php.hardcoded-iv
        openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, '1234567890123456');
        $fixedIv = "0000000000000000";
        // ruleid: enqrypta.misuse.php.hardcoded-iv
        openssl_decrypt($data, 'aes-256-cbc', $key, 0, $fixedIv);
        // ruleid: enqrypta.misuse.php.hardcoded-iv
        openssl_encrypt($data, 'aes-128-cbc', $key, 0, str_repeat("\0", 16));
        // ruleid: enqrypta.misuse.php.hardcoded-iv
        sodium_crypto_secretbox($msg, '012345678901234567890123', $key);
        // ruleid: enqrypta.misuse.php.hardcoded-iv
        openssl_encrypt($data, 'aes-256-gcm', $key, 0, iv: 'abcdefabcdef', tag: $tag);
        // ok: enqrypta.misuse.php.hardcoded-iv
        openssl_encrypt($data, 'aes-256-cbc', $key, 0, random_bytes(16));
        // ok: enqrypta.misuse.php.hardcoded-iv
        openssl_encrypt($data, 'aes-256-cbc', $key, 0, '');
        // ruleid: enqrypta.misuse.php.hardcoded-key
        openssl_encrypt($data, 'aes-256-cbc', 'my-super-secret-key', 0, $iv);
        // ruleid: enqrypta.misuse.php.hardcoded-key
        hash_hmac('sha256', $data, 'webhook-signing-secret');
        // ruleid: enqrypta.misuse.php.hardcoded-key
        new Encrypter('base64:2fl+Ktvkfl+Fuz4Qp/A75G2RTiWVA/ZoKZvp6fiiM10=', 'AES-256-CBC');
        // ruleid: enqrypta.misuse.php.hardcoded-key
        JWT::encode($payload, 'jwt-secret', 'HS256');
        // ruleid: enqrypta.misuse.php.hardcoded-key
        JWT::decode($jwt, new Key('jwt-secret', 'HS256'));
        // ok: enqrypta.misuse.php.hardcoded-key
        openssl_encrypt($data, 'aes-256-cbc', config('app.key'), 0, $iv);
        // ok: enqrypta.misuse.php.hardcoded-key
        hash_hmac('sha256', $data, env('WEBHOOK_SECRET'));
    }
}

function app_config()
{
    return [
        'cipher' => 'AES-256-CBC',
        // ruleid: enqrypta.misuse.php.hardcoded-key
        'key' => 'base64:2fl+Ktvkfl+Fuz4Qp/A75G2RTiWVA/ZoKZvp6fiiM10=',
    ];
}

function safe_app_config()
{
    return [
        'cipher' => 'AES-256-CBC',
        // ok: enqrypta.misuse.php.hardcoded-key
        'key' => env('APP_KEY'),
    ];
}

class Transport
{
    public function http($ch, $url)
    {
        // ruleid: enqrypta.misuse.php.tls-verify-disabled
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        // ruleid: enqrypta.misuse.php.tls-verify-disabled
        curl_setopt($ch, \CURLOPT_SSL_VERIFYHOST, 0);
        // ruleid: enqrypta.misuse.php.tls-verify-disabled
        curl_setopt_array($ch, [CURLOPT_URL => $url, CURLOPT_SSL_VERIFYPEER => FALSE]);
        // ruleid: enqrypta.misuse.php.tls-verify-disabled
        $client = new Client(['base_uri' => $url, 'verify' => false]);
        // ruleid: enqrypta.misuse.php.tls-verify-disabled
        $client->request('GET', $url, [RequestOptions::VERIFY => false]);
        // ruleid: enqrypta.misuse.php.tls-verify-disabled
        Http::withoutVerifying()->get($url);
        // ruleid: enqrypta.misuse.php.tls-verify-disabled
        $context = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
        // ruleid: enqrypta.misuse.php.tls-verify-disabled
        $response = wp_remote_get($url, ['timeout' => 10, 'sslverify' => false]);
        // ruleid: enqrypta.misuse.php.tls-verify-disabled
        add_filter('https_ssl_verify', '__return_false');
        // ruleid: enqrypta.misuse.php.tls-verify-disabled
        $mail->SMTPOptions = ['ssl' => ['allow_self_signed' => true]];
        // ruleid: enqrypta.misuse.php.tls-verify-disabled
        $symfony = HttpClient::create(['verify_host' => false]);
        // ok: enqrypta.misuse.php.tls-verify-disabled
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        // ok: enqrypta.misuse.php.tls-verify-disabled
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        // ok: enqrypta.misuse.php.tls-verify-disabled
        $client = new Client(['base_uri' => $url, 'verify' => '/etc/ssl/certs/ca.pem']);
        // ok: enqrypta.misuse.php.tls-verify-disabled
        $rules = ['email' => 'required', 'verify' => false];
        // ruleid: enqrypta.misuse.php.weak-tls-version
        curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_0);
        // ruleid: enqrypta.misuse.php.weak-tls-version
        curl_setopt($ch, CURLOPT_SSLVERSION, 3);
        // ruleid: enqrypta.misuse.php.weak-tls-version
        curl_setopt_array($ch, [CURLOPT_SSLVERSION => \CURL_SSLVERSION_TLSv1_1]);
        // ruleid: enqrypta.misuse.php.weak-tls-version
        stream_context_create(['ssl' => ['crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT]]);
        // ruleid: enqrypta.misuse.php.weak-tls-version
        stream_socket_client('sslv3://legacy.example.com:443', $errno, $errstr);
        // ok: enqrypta.misuse.php.weak-tls-version
        curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
        // ok: enqrypta.misuse.php.weak-tls-version
        curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        // ok: enqrypta.misuse.php.weak-tls-version
        stream_socket_client('tls://api.example.com:443', $errno, $errstr);
    }

    public function databases($pdo, $link)
    {
        $options = [
            // ruleid: enqrypta.misuse.php.db-tls-verify-disabled
            \PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false,
        ];
        // ruleid: enqrypta.misuse.php.db-tls-verify-disabled
        $pdo->setAttribute(PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT, false);
        // ruleid: enqrypta.misuse.php.db-tls-verify-disabled
        mysqli_real_connect($link, $host, $user, $pass, $db, 3306, null, MYSQLI_CLIENT_SSL_DONT_VERIFY_SERVER_CERT);
        // ruleid: enqrypta.misuse.php.db-tls-verify-disabled
        $pgsql = ['driver' => 'pgsql', 'sslmode' => 'disable'];
        // ruleid: enqrypta.misuse.php.db-tls-verify-disabled
        $pgsql = ['driver' => 'pgsql', 'sslmode' => env('DB_SSLMODE', 'allow')];
        // ruleid: enqrypta.misuse.php.db-tls-verify-disabled
        $conn = new \PDO('pgsql:host=db.internal;dbname=app;sslmode=disable', $user, $pass);
        // ok: enqrypta.misuse.php.db-tls-verify-disabled
        $pgsql = ['driver' => 'pgsql', 'sslmode' => 'verify-full'];
        // ok: enqrypta.misuse.php.db-tls-verify-disabled
        $pdo->setAttribute(PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT, true);
    }
}

class Keys
{
    public function sizes($data)
    {
        // ruleid: enqrypta.misuse.php.weak-key-size
        openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $config = ['private_key_bits' => 512];
        // ruleid: enqrypta.misuse.php.weak-key-size
        openssl_pkey_new($config);
        // ruleid: enqrypta.misuse.php.weak-key-size
        RSA::createKey(1024);
        // ruleid: enqrypta.misuse.php.weak-key-size
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime192v1']);
        // ruleid: enqrypta.misuse.php.weak-key-size
        EC::createKey('secp160r1');
        // ok: enqrypta.misuse.php.weak-key-size
        openssl_pkey_new(['private_key_bits' => 3072]);
        // ok: enqrypta.misuse.php.weak-key-size
        EC::createKey('secp256r1');
        // ruleid: enqrypta.misuse.php.rsa-pkcs1v15-encryption
        openssl_public_encrypt($data, $encrypted, $pub);
        // ruleid: enqrypta.misuse.php.rsa-pkcs1v15-encryption
        openssl_private_decrypt($data, $plain, $priv, OPENSSL_PKCS1_PADDING);
        // ruleid: enqrypta.misuse.php.rsa-pkcs1v15-encryption
        openssl_public_encrypt($data, $encrypted, $pub, \OPENSSL_NO_PADDING);
        // ruleid: enqrypta.misuse.php.rsa-pkcs1v15-encryption
        $key->withPadding(RSA::ENCRYPTION_PKCS1);
        // ok: enqrypta.misuse.php.rsa-pkcs1v15-encryption
        openssl_public_encrypt($data, $encrypted, $pub, OPENSSL_PKCS1_OAEP_PADDING);
        // ok: enqrypta.misuse.php.rsa-pkcs1v15-encryption
        openssl_private_encrypt($digest, $signature, $priv);
        // ruleid: enqrypta.misuse.php.legacy-default-cipher
        openssl_seal($data, $sealed, $envKeys, [$pub]);
        // ruleid: enqrypta.misuse.php.legacy-default-cipher
        openssl_pkcs7_encrypt($in, $out, $cert, $headers);
        // ruleid: enqrypta.misuse.php.legacy-default-cipher
        openssl_pkcs7_encrypt($in, $out, $cert, $headers, 0, OPENSSL_CIPHER_RC2_40);
        // ok: enqrypta.misuse.php.legacy-default-cipher
        openssl_seal($data, $sealed, $envKeys, [$pub], 'aes-256-cbc', $iv);
        // ok: enqrypta.misuse.php.legacy-default-cipher
        openssl_pkcs7_encrypt($in, $out, $cert, $headers, 0, OPENSSL_CIPHER_AES_256_CBC);
    }
}

class Verification
{
    public function compare($payload, $secret, $signature, $password, $stored)
    {
        // ruleid: enqrypta.misuse.php.insecure-mac-compare
        if (hash_hmac('sha256', $payload, $secret) == $signature) {
        }
        $expected = hash_hmac('sha256', $payload, $secret);
        // ruleid: enqrypta.misuse.php.insecure-mac-compare
        if ($signature === $expected) {
        }
        // ruleid: enqrypta.misuse.php.insecure-mac-compare
        if (strcmp(crypt($password, $stored), $stored) == 0) {
        }
        // ruleid: enqrypta.misuse.php.insecure-mac-compare
        if (md5($payload . $secret) == $request_signature) {
        }
        // ok: enqrypta.misuse.php.insecure-mac-compare
        if (hash_equals(hash_hmac('sha256', $payload, $secret), $signature)) {
        }
        // ok: enqrypta.misuse.php.insecure-mac-compare
        if (md5_file($path) == $etag) {
        }
        // ok: enqrypta.misuse.php.insecure-mac-compare
        if (hash_hmac('sha256', $payload, $secret) === false) {
        }
    }

    public function tokens($jwt, $key)
    {
        // ruleid: enqrypta.misuse.php.jwt-unsafe-verification
        JWT::decode($jwt, $key, ['HS256', 'RS256']);
        // ruleid: enqrypta.misuse.php.jwt-unsafe-verification
        Configuration::forUnsecuredSigner();
        // ruleid: enqrypta.misuse.php.jwt-unsafe-verification
        new \Lcobucci\JWT\Signer\None();
        // ok: enqrypta.misuse.php.jwt-unsafe-verification
        JWT::decode($jwt, $key, ['RS256']);
        // ok: enqrypta.misuse.php.jwt-unsafe-verification
        Configuration::forSymmetricSigner($signer, $key);
    }

    public function passwords($password, $user)
    {
        // ruleid: enqrypta.misuse.php.weak-kdf
        hash_pbkdf2('sha1', $password, $salt, 100000);
        // ruleid: enqrypta.misuse.php.weak-kdf
        hash_pbkdf2('sha256', $password, $salt, 1000);
        // ruleid: enqrypta.misuse.php.weak-kdf
        password_hash($password, PASSWORD_BCRYPT, ['cost' => 4]);
        // ruleid: enqrypta.misuse.php.weak-kdf, enqrypta.misuse.php.hardcoded-salt
        crypt($password, '$1$saltsalt$');
        // ok: enqrypta.misuse.php.weak-kdf
        hash_pbkdf2('sha256', $password, $salt, 600000);
        // ok: enqrypta.misuse.php.weak-kdf
        password_hash($password, PASSWORD_ARGON2ID);
        // ruleid: enqrypta.misuse.php.weak-password-hash
        $hash = md5($password);
        // ruleid: enqrypta.misuse.php.weak-password-hash
        $hash = sha1($user->password . $salt);
        // ruleid: enqrypta.misuse.php.weak-password-hash
        $hash = hash('sha256', $new_password);
        // ok: enqrypta.misuse.php.weak-password-hash
        $hash = password_hash($password, PASSWORD_DEFAULT);
        // ok: enqrypta.misuse.php.weak-password-hash
        $hash = md5($passport_number);
        // ruleid: enqrypta.misuse.php.hardcoded-salt
        hash_pbkdf2('sha256', $password, 'static-salt', 600000);
        // ruleid: enqrypta.misuse.php.hardcoded-salt
        sodium_crypto_pwhash(32, $password, 'sixteen-byte-sal', $ops, $mem);
        // ruleid: enqrypta.misuse.php.hardcoded-salt
        password_hash($password, PASSWORD_BCRYPT, ['salt' => $fixedSalt]);
        // ok: enqrypta.misuse.php.hardcoded-salt
        hash_pbkdf2('sha256', $password, random_bytes(16), 600000);
    }
}

class ShortTokens
{
    public function tokens()
    {
        // ruleid: enqrypta.misuse.php.short-random-token
        $this->csrfToken = bin2hex(random_bytes(8));
        // ok: enqrypta.misuse.php.short-random-token
        $sessionToken = bin2hex(random_bytes(32));
        // ruleid: enqrypta.misuse.php.short-random-token
        $resetToken = openssl_random_pseudo_bytes(10);
        // ok: enqrypta.misuse.php.short-random-token
        $salt = random_bytes(8);
        return [$sessionToken, $resetToken, $salt];
    }
}

