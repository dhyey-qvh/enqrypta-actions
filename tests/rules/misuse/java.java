import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import org.apache.http.conn.ssl.NoopHostnameVerifier;

class Misuse {
    static final String SECRET = "0123456789abcdef";

    void weakCiphers() throws Exception {
        // ruleid: enqrypta.misuse.java.weak-cipher-3des
        Cipher.getInstance("DESede/CBC/PKCS5Padding");
        // ok: enqrypta.misuse.java.weak-cipher-3des
        Cipher.getInstance("AES/GCM/NoPadding");
        // ruleid: enqrypta.misuse.java.weak-cipher-des
        Cipher.getInstance("DES/CBC/PKCS5Padding");
        // ok: enqrypta.misuse.java.weak-cipher-des
        Cipher.getInstance("ChaCha20-Poly1305");
        // ruleid: enqrypta.misuse.java.weak-cipher-rc4
        Cipher.getInstance("ARCFOUR");
        // ok: enqrypta.misuse.java.weak-cipher-rc4
        Cipher.getInstance("ChaCha20");
        // ruleid: enqrypta.misuse.java.weak-cipher-blowfish
        Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        // ok: enqrypta.misuse.java.weak-cipher-blowfish
        Cipher.getInstance("Camellia/GCM/NoPadding");
    }

    void modes() throws Exception {
        // ruleid: enqrypta.misuse.java.ecb-mode
        Cipher.getInstance("AES");
        // ruleid: enqrypta.misuse.java.ecb-mode
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ok: enqrypta.misuse.java.ecb-mode
        Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    void weakHashes() throws Exception {
        // ruleid: enqrypta.misuse.java.sha1-signature
        Signature.getInstance("SHA1withRSA");
        // ok: enqrypta.misuse.java.sha1-signature
        Signature.getInstance("SHA256withRSA");
        // ruleid: enqrypta.misuse.java.md5-signature-or-mac
        Signature.getInstance("MD5withRSA");
        // ruleid: enqrypta.misuse.java.md5-signature-or-mac
        Mac.getInstance("HmacMD5");
        // ok: enqrypta.misuse.java.md5-signature-or-mac
        Mac.getInstance("HmacSHA256");
    }

    void randomness() {
        Random random = new Random();
        byte[] ivBytes = new byte[16];
        // ruleid: enqrypta.misuse.java.insecure-random
        random.nextBytes(ivBytes);
        byte[] sessionToken = new byte[32];
        // ruleid: enqrypta.misuse.java.insecure-random
        new Random().nextBytes(sessionToken);
        byte[] noise = new byte[8];
        // ok: enqrypta.misuse.java.insecure-random
        random.nextBytes(noise);
        SecureRandom secure = new SecureRandom();
        byte[] aesKey = new byte[32];
        // ok: enqrypta.misuse.java.insecure-random
        secure.nextBytes(aesKey);
    }

    void fixedIvsAndKeys(byte[] iv, byte[] key) {
        // ruleid: enqrypta.misuse.java.hardcoded-iv
        new IvParameterSpec("1234567890123456".getBytes());
        // ruleid: enqrypta.misuse.java.hardcoded-iv
        new IvParameterSpec(new byte[16]);
        // ruleid: enqrypta.misuse.java.hardcoded-iv
        new GCMParameterSpec(128, new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
        // ok: enqrypta.misuse.java.hardcoded-iv
        new GCMParameterSpec(128, iv);
        // ruleid: enqrypta.misuse.java.hardcoded-key
        new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        // ruleid: enqrypta.misuse.java.hardcoded-key
        new SecretKeySpec(SECRET.getBytes(), "AES");
        // ok: enqrypta.misuse.java.hardcoded-key
        new SecretKeySpec(key, "AES");
    }

    void weakTls() throws Exception {
        // ruleid: enqrypta.misuse.java.weak-tls-version
        SSLContext.getInstance("TLSv1");
        // ruleid: enqrypta.misuse.java.weak-tls-version
        SSLContext.getInstance("SSL");
        // ok: enqrypta.misuse.java.weak-tls-version
        SSLContext.getInstance("TLSv1.3");
    }

    void hostnames(HttpsURLConnection connection) {
        // ruleid: enqrypta.misuse.java.tls-verify-disabled
        connection.setHostnameVerifier((host, session) -> true);
        // ruleid: enqrypta.misuse.java.tls-verify-disabled
        HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true);
        // ruleid: enqrypta.misuse.java.tls-verify-disabled
        Object noop = NoopHostnameVerifier.INSTANCE;
        // ok: enqrypta.misuse.java.tls-verify-disabled
        connection.setHostnameVerifier((host, session) -> host.equals("api.example.com"));
    }
}

class TrustEverything implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    // ruleid: enqrypta.misuse.java.tls-verify-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

class StrictTrust implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    // ok: enqrypta.misuse.java.tls-verify-disabled
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
        delegate.checkServerTrusted(chain, authType);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

class AllowAll implements HostnameVerifier {
    // ruleid: enqrypta.misuse.java.tls-verify-disabled
    public boolean verify(String hostname, SSLSession session) { return true; }
}
