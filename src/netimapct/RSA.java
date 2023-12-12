/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package netimapct;

import javax.crypto.Cipher;
import java.security.*;

import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RSA {
    Connection con;
    public RSA(){
        try {
            con = DriverManager.getConnection("jdbc:mysql://localhost:3306/netpackt","root","0238736729@nN");
        } catch (SQLException ex) {
            Logger.getLogger(login.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void generateKeysNew(String username){
        try {
            
            //notes
            //byte[] retrievedEncodedPublicKey = hexToBytes(puplickeystored);
            //PublicKey decodedPublicKey = decodePublicKey(encodedPublicKey);
            // end notes
            
            // generating keypair
            KeyPair keyPair = generateKeyPair();
            //getting public key
            PublicKey publicKey = keyPair.getPublic();
            // encoding public key
            byte[] encodedPublicKey = publicKey.getEncoded();
            // converting encoded public key to string to insert in database
            String puplickeystored = bytesToHex(encodedPublicKey);
            System.out.println(puplickeystored.length());
            //getting private key
            PrivateKey privateKey = keyPair.getPrivate();
            // encoding private key
            byte[] encodedPrivateKey = privateKey.getEncoded();
            // converting it to string to store in database
            String privatekeystored = bytesToHex(encodedPrivateKey);
            System.out.println(privatekeystored.length());
            PreparedStatement stmt = con.prepareStatement("INSERT INTO netpackt.keys (username, public_key, private_key) values (?, ?, ?)");
            stmt.setString(1, username);
            stmt.setString(2, puplickeystored);
            stmt.setString(3, privatekeystored);
            stmt.executeUpdate();

            
        } catch (NoSuchAlgorithmException | SQLException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    public static void main(String[] args) {
        try {
//            // Generate key pair
//            
//
//            // Get public and private keys
//            PublicKey publicKey = keyPair.getPublic();
//            
//            PrivateKey privateKey = keyPair.getPrivate();
//
//            // Original message
//            String originalMessage = "Hello, RSA!";
//
//            // Encrypt the message using the public key
//            byte[] encryptedMessage = encrypt(originalMessage, publicKey);
//
//            // Decrypt the message using the private key
//            String decryptedMessage = decrypt(encryptedMessage, privateKey);
//
//            // Print results
//            System.out.println("Original message: " + originalMessage);
//            System.out.println("Encrypted message: " + bytesToHex(encryptedMessage));
//            System.out.println("Decrypted message: " + decryptedMessage);

        } catch (Exception e) {
            
        }
    }
    private static PublicKey decodePublicKey(byte[] encodedPublicKeyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedPublicKeyBytes);
        return keyFactory.generatePublic(keySpec);
    }
    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // You can choose the key size (2048 bits is common)
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText.getBytes());
    }

    private static String decrypt(byte[] encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedText);
        return new String(decryptedBytes);
    }

    // Helper method to convert byte array to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexStringBuilder = new StringBuilder();
        for (byte b : bytes) {
            hexStringBuilder.append(String.format("%02X", b));
        }
        return hexStringBuilder.toString();
    }
    
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
