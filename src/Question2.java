import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.util.Base64;

public class Question2 {

    public static void main(String[] args) throws Exception {

        String plaintext = "Ngonidzashe Mangudya H180202M SE";

        // Generate two keys for DES-2 encryption
        SecretKey key1 = generateDESKey();
        SecretKey key2 = generateDESKey();

        // Encrypt plaintext using two keys
        String ciphertext2 = encryptDES2(plaintext, key1, key2);
        System.out.println("Encrypted using DES-2: " + ciphertext2);

        // Decrypt ciphertext using two keys
        String decrypted2 = decryptDES2(ciphertext2, key1, key2);
        System.out.println("Decrypted using DES-2: " + decrypted2);

        // Generate three keys for DES-3 encryption
        SecretKey key3 = generateDESKey();

        // Encrypt plaintext using three keys
        String ciphertext3 = encryptDES3(plaintext, key1, key2, key3);
        System.out.println("Encrypted using DES-3: " + ciphertext3);

        // Decrypt ciphertext using three keys
        String decrypted3 = decryptDES3(ciphertext3, key1, key2, key3);
        System.out.println("Decrypted using DES-3: " + decrypted3);
    }

    private static SecretKey generateDESKey() throws Exception {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        DESedeKeySpec keySpec = new DESedeKeySpec(new byte[24]);
        return keyFactory.generateSecret(keySpec);
    }

    private static String encryptDES2(String plaintext, SecretKey key1, SecretKey key2) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key1);
        cipher.init(Cipher.ENCRYPT_MODE, key2);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptDES2(String ciphertext, SecretKey key1, SecretKey key2) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key2);
        cipher.init(Cipher.DECRYPT_MODE, key1);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes).trim();
    }

    private static String encryptDES3(String plaintext, SecretKey key1, SecretKey key2, SecretKey key3) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key1);
        cipher.init(Cipher.ENCRYPT_MODE, key2);
        cipher.init(Cipher.ENCRYPT_MODE, key3);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptDES3(String ciphertext, SecretKey key1, SecretKey key2, SecretKey key3) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key3);
        cipher.init(Cipher.DECRYPT_MODE, key2);
        cipher.init(Cipher.DECRYPT_MODE, key1);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes).trim();
    }
}