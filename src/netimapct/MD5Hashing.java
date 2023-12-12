/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Interface.java to edit this template
 */
package netimapct;

/**
 *
 * @author mohab
 */
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Hashing {

    public static String md5(String input) {
        try {
            // Get MD5 instance
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // Add data to digest
            md.update(input.getBytes());

            // Get the hash value
            byte[] hashBytes = md.digest();

            // Convert the byte array to a hexadecimal string
            StringBuilder hexString = new StringBuilder();
            for (byte hashByte : hashBytes) {
                hexString.append(String.format("%02x", hashByte));
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            // Handle the exception (e.g., log it, throw a custom exception, etc.)
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        // Example usage
        String plainTextPassword = "mySecretPassword";
        String hashedPassword = md5(plainTextPassword);

        System.out.println("Original Password: " + plainTextPassword);
        System.out.println("MD5 Hashed Password: " + hashedPassword);
    }
}
