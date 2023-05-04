package Question6;

public class CaesarCipher {

    private static final int ALPHABET_SIZE = 26;

    /**
     * Encrypts a plaintext message using the Caesar cipher.
     *
     * @param message the plaintext message to encrypt
     * @param shift the number of positions to shift each character
     * @return the encrypted message
     */
    public static String encrypt(String message, int shift) {
        StringBuilder result = new StringBuilder();
        for (char c : message.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                c = (char) ((c - base + shift) % ALPHABET_SIZE + base);
            }
            result.append(c);
        }
        return result.toString();
    }

    /**
     * Decrypts a ciphertext message using the Caesar cipher.
     *
     * @param ciphertext the ciphertext message to decrypt
     * @param shift the number of positions to shift each character
     * @return the decrypted message
     */
    public static String decrypt(String ciphertext, int shift) {
        return encrypt(ciphertext, ALPHABET_SIZE - shift);
    }

    public static void main(String[] args) {
        String message = "Ngonidzashe Mangudya H180202M SE";
        int shift = 3;

        String encryptedMessage = encrypt(message, shift);
        System.out.println("Encrypted message: " + encryptedMessage);

        String decryptedMessage = decrypt(encryptedMessage, shift);
        System.out.println("Decrypted message: " + decryptedMessage);
    }
}
