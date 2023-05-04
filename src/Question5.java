import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Question5 {

    private static final int SALT_LENGTH = 16; // Length of the salt in bytes
    private static final int ITERATIONS = 10000; // Number of iterations for the hash function

    /**
     * Encrypts a plaintext password using the SHA-256 hash function and a random salt.
     *
     * @param password the plaintext password to encrypt
     * @return a string containing the encrypted password and the salt, separated by a colon
     * @throws NoSuchAlgorithmException if the SHA-256 algorithm is not available
     */
    public static String encryptPassword(String password) throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = saltedHash(digest, password.getBytes(), salt);

        String encodedSalt = Base64.getEncoder().encodeToString(salt);
        String encodedHash = Base64.getEncoder().encodeToString(hash);

        return encodedHash + ":" + encodedSalt;
    }

    /**
     * Verifies a plaintext password against an encrypted password.
     *
     * @param password the plaintext password to verify
     * @param encryptedPassword the encrypted password to verify against
     * @return true if the plaintext password matches the encrypted password, false otherwise
     * @throws NoSuchAlgorithmException if the SHA-256 algorithm is not available
     */
    public static boolean verifyPassword(String password, String encryptedPassword) throws NoSuchAlgorithmException {
        String[] parts = encryptedPassword.split(":");
        if (parts.length != 2) {
            return false;
        }

        byte[] hash = Base64.getDecoder().decode(parts[0]);
        byte[] salt = Base64.getDecoder().decode(parts[1]);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] testHash = saltedHash(digest, password.getBytes(), salt);

        return MessageDigest.isEqual(hash, testHash);
    }

    /**
     * Computes a salted hash of the input data.
     *
     * @param digest the hash function to use
     * @param input the input data to hash
     * @param salt the salt to use
     * @return the salted hash of the input data
     */
    private static byte[] saltedHash(MessageDigest digest, byte[] input, byte[] salt) {
        digest.reset();
        digest.update(salt);
        byte[] hash = digest.digest(input);

        for (int i = 0; i < ITERATIONS - 1; i++) {
            digest.reset();
            hash = digest.digest(hash);
        }

        byte[] saltedHash = new byte[hash.length + salt.length];
        System.arraycopy(hash, 0, saltedHash, 0, hash.length);
        System.arraycopy(salt, 0, saltedHash, hash.length, salt.length);

        return saltedHash;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String password = "password123";

        String encryptedPassword = encryptPassword(password);
        System.out.println("Encrypted password: " + encryptedPassword);

        boolean verified = verifyPassword(password, encryptedPassword);
        System.out.println("Password verification: " + verified);
    }
}
