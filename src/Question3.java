import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

public class Question3 {

    public static void main(String[] args) throws Exception {
        String plaintext = "Ngonidzashe Mangudya H180202M SE";

        // Generate public and private keys
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypt the plaintext using the public key
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        System.out.println("Encrypted ciphertext: " + new String(ciphertext));

        // Decrypt the ciphertext using the private key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        String decryptedPlaintext = new String(decryptedBytes);
        System.out.println("Decrypted plaintext: " + decryptedPlaintext);
    }
}
