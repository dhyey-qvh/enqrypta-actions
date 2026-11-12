import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.MLDSAParameterSpec;
import java.security.spec.MLKEMParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import org.apache.commons.codec.digest.DigestUtils;

class Inventory {
    static final String TRANSFORMATION = "AES/GCM/NoPadding";

    void ciphers(String transformation) throws Exception {
        // ruleid: enqrypta.crypto.java.aes-cipher
        Cipher.getInstance("AES/GCM/NoPadding");
        // ruleid: enqrypta.crypto.java.aes-cipher
        Cipher.getInstance("AES_256/CBC/PKCS5Padding", "BC");
        // ok: enqrypta.crypto.java.aes-cipher
        Cipher.getInstance("ChaCha20-Poly1305");
        // ok: enqrypta.crypto.java.aes-cipher
        Cipher.getInstance(transformation);
        // ruleid: enqrypta.crypto.java.rsa-cipher
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        // ok: enqrypta.crypto.java.rsa-cipher
        Cipher.getInstance("ChaCha20");
    }

    void signatures() throws Exception {
        // ruleid: enqrypta.crypto.java.rsa-signature
        Signature.getInstance("SHA256withRSA");
        // ruleid: enqrypta.crypto.java.rsa-signature
        Signature.getInstance("RSASSA-PSS");
        // ok: enqrypta.crypto.java.rsa-signature
        Signature.getInstance("Ed448");
        // ruleid: enqrypta.crypto.java.ecdsa-signature
        Signature.getInstance("SHA384withECDSA");
        // ok: enqrypta.crypto.java.ecdsa-signature
        Signature.getInstance("SHA384withDSA");
        // ruleid: enqrypta.crypto.java.ed25519
        Signature.getInstance("Ed25519");
        // ruleid: enqrypta.crypto.java.ed25519
        KeyPairGenerator.getInstance("EdDSA");
        // ok: enqrypta.crypto.java.ed25519
        KeyPairGenerator.getInstance("EC");
    }

    void rsaKeys(int bits) throws Exception {
        KeyPairGenerator sized = KeyPairGenerator.getInstance("RSA");
        // ruleid: enqrypta.crypto.java.rsa-keygen
        sized.initialize(3072);
        KeyPairGenerator variable = KeyPairGenerator.getInstance("RSA");
        // ruleid: enqrypta.crypto.java.rsa-keygen
        variable.initialize(bits);
        // ruleid: enqrypta.crypto.java.rsa-keygen
        KeyPairGenerator.getInstance("RSA").generateKeyPair();
        // ok: enqrypta.crypto.java.rsa-keygen
        KeyPairGenerator.getInstance("DSA");
    }

    void agreements() throws Exception {
        // ruleid: enqrypta.crypto.java.ecdh
        KeyAgreement.getInstance("ECDH");
        // ok: enqrypta.crypto.java.ecdh
        KeyAgreement.getInstance("ECMQV");
        // ruleid: enqrypta.crypto.java.x25519
        KeyAgreement.getInstance("X25519");
        // ruleid: enqrypta.crypto.java.x25519
        KeyPairGenerator.getInstance("XDH");
        // ok: enqrypta.crypto.java.x25519
        KeyAgreement.getInstance("X448");
        // ruleid: enqrypta.crypto.java.dh
        KeyAgreement.getInstance("DiffieHellman");
        // ok: enqrypta.crypto.java.dh
        KeyAgreement.getInstance("ECMQV");
    }

    void digests(byte[] data) throws Exception {
        // ruleid: enqrypta.crypto.java.sha1
        MessageDigest.getInstance("SHA-1");
        // ruleid: enqrypta.crypto.java.sha1
        DigestUtils.sha1Hex(data);
        // ok: enqrypta.crypto.java.sha1
        MessageDigest.getInstance("SHA-256");
        // ruleid: enqrypta.crypto.java.md5
        MessageDigest.getInstance("MD5");
        // ruleid: enqrypta.crypto.java.md5
        DigestUtils.md5Hex(data);
        // ok: enqrypta.crypto.java.md5
        DigestUtils.sha256Hex(data);
    }

    void postQuantum() throws Exception {
        // ruleid: enqrypta.crypto.java.ml-kem
        KeyPairGenerator.getInstance("ML-KEM-768");
        // ruleid: enqrypta.crypto.java.ml-kem
        KEM.getInstance("ML-KEM");
        // ruleid: enqrypta.crypto.java.ml-kem
        Object kemSpec = MLKEMParameterSpec.ml_kem_1024;
        // ok: enqrypta.crypto.java.ml-kem
        KEM.getInstance("DHKEM");
        // ruleid: enqrypta.crypto.java.ml-dsa
        Signature.getInstance("ML-DSA-65");
        // ruleid: enqrypta.crypto.java.ml-dsa
        Object dsaSpec = MLDSAParameterSpec.ml_dsa_87;
        // ok: enqrypta.crypto.java.ml-dsa
        Signature.getInstance("SLH-DSA-SHA2-128S");
    }
}
