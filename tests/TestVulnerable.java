import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.KeyAgreement;

public class TestVulnerable {
    public static void main(String[] args) throws Exception {

        // RSA - QUANTUM VULNERABLE
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);

        // ECC - QUANTUM VULNERABLE
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");

        // DH - QUANTUM VULNERABLE
        KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");

        // MD5 - QUANTUM VULNERABLE
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        // SHA1 - QUANTUM VULNERABLE
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    }
}