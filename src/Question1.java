
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

public class Question1 {
    public static void main(String[] args) throws Exception {
        String plaintext = "Ngonidzashe Mangudya H180202M SE";
        System.out.println(plaintext.length());
        SecretKey key = generateKey();
        byte[] initialization_vector = { 22, 33, 11, 44, 55, 99, 66, 77 };
        AlgorithmParameterSpec aps = new IvParameterSpec(initialization_vector);
        String ciphertext = encrypt(plaintext, key, aps);
        System.out.println("Encrypted text: " + ciphertext);
        String decryptedText = decrypt(ciphertext, key, aps);
        System.out.println("Decrypted text: " + decryptedText);
    }

    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        return keyGenerator.generateKey();
    }

    private static String encrypt(String plaintext, SecretKey key, AlgorithmParameterSpec spec) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return new String(encryptedBytes);
    }

    private static String decrypt(String ciphertext, SecretKey key, AlgorithmParameterSpec spec) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = cipher.doFinal(ciphertext.getBytes());
        return new String(decryptedBytes).trim();
    }
}
