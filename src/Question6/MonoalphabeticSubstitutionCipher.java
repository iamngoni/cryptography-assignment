package Question6;

public class MonoalphabeticSubstitutionCipher {

    /**
     * Encrypts a plaintext message using a monoalphabetic substitution cipher.
     *
     * @param message the plaintext message to encrypt
     * @param key the substitution key to use for encryption
     * @return the encrypted message
     */
    public static String encrypt(String message, String key) {
        StringBuilder result = new StringBuilder();
        for (char c : message.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                int index = c - base;
                c = key.charAt(index);
            }
            result.append(c);
        }
        return result.toString();
    }

    /**
     * Decrypts a ciphertext message using a monoalphabetic substitution cipher.
     *
     * @param ciphertext the ciphertext message to decrypt
     * @param key the substitution key to use for decryption
     * @return the decrypted message
     */
    public static String decrypt(String ciphertext, String key) {
        StringBuilder result = new StringBuilder();
        for (char c : ciphertext.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                int index = key.indexOf(c);
                c = (char) (index + base);
            }
            result.append(c);
        }
        return result.toString();
    }

    public static void main(String[] args) {
        String message = "Ngonidzashe Mangudya H180202M SE";
        String key = "qwertyuiopasdfghjklzxcvbnm";

        String encryptedMessage = encrypt(message, key);
        System.out.println("Encrypted message: " + encryptedMessage);

        String decryptedMessage = decrypt(encryptedMessage, key);
        System.out.println("Decrypted message: " + decryptedMessage);
    }
}
