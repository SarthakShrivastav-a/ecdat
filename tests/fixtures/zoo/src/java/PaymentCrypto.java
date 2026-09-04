// truth: AES/CBC/PKCS5Padding cipher, RSA-2048 keypair, SHA256withECDSA signature, MD5 digest, DESede legacy cipher
import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

public class PaymentCrypto {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    {
        kpg.initialize(2048);
    }
    Signature sig = Signature.getInstance("SHA256withECDSA");
    MessageDigest md = MessageDigest.getInstance("MD5");
    Cipher legacy = Cipher.getInstance("DESede/CBC/PKCS5Padding");
}
