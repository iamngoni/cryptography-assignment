import java.security.MessageDigest;

public class Question4 {

    public static void main(String[] args) throws Exception {
        String plaintext = "Hello, world!";

        // Create a SHA-1 message digest object
        MessageDigest md = MessageDigest.getInstance("SHA-1");

        // Update the message digest with the plaintext
        md.update(plaintext.getBytes());

        // Calculate the message digest
        byte[] digest = md.digest();

        // Convert the message digest to a hexadecimal string
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        String hexDigest = sb.toString();

        System.out.println("SHA-1 message digest: " + hexDigest);
    }
}
