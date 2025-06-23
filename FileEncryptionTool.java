import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class FileEncryptionTool {

    // Method to hash the password and derive a secure AES key
    public static SecretKey getKeyFromPassword(String password) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = sha.digest(password.getBytes("UTF-8"));
        key = Arrays.copyOf(key, 16);
        return new SecretKeySpec(key, "AES");
    }

    // Encrypt a file
    public static void encryptFile(String inputFile, String outputFile, String password) throws Exception {
        SecretKey secretKey = getKeyFromPassword(password);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        processFile(cipher, inputFile, outputFile);
        System.out.println("✅ File Encrypted Successfully: " + outputFile);
    }

    // Decrypt a file
    public static void decryptFile(String inputFile, String outputFile, String password) throws Exception {
        SecretKey secretKey = getKeyFromPassword(password);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        processFile(cipher, inputFile, outputFile);
        System.out.println("✅ File Decrypted Successfully: " + outputFile);
    }

    // Common method to process file for encryption/decryption
    private static void processFile(Cipher cipher, String inputFile, String outputFile) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile);
             CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
        }
    }

    // Hide password input
    public static String getHiddenPassword() {
        Console console = System.console();
        if (console == null) {
            throw new RuntimeException("No console available. Run in a proper terminal.");
        }
        char[] passwordArray = console.readPassword("Enter Password: ");
        return new String(passwordArray);
    }

    // CLI Usage
    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage:");
            System.out.println("  Encrypt: java FileEncryptionTool encrypt <inputFile> <outputFile>");
            System.out.println("  Decrypt: java FileEncryptionTool decrypt <inputFile> <outputFile>");
            return;
        }

        String operation = args[0];
        String inputFile = args[1];
        String outputFile = args[2];

        try {
            String password = getHiddenPassword();
            if ("encrypt".equalsIgnoreCase(operation)) {
                encryptFile(inputFile, outputFile, password);
            } else if ("decrypt".equalsIgnoreCase(operation)) {
                decryptFile(inputFile, outputFile, password);
            } else {
                System.out.println("Invalid operation. Use 'encrypt' or 'decrypt'.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(" Error: " + e.getMessage());
        }
    }
}
