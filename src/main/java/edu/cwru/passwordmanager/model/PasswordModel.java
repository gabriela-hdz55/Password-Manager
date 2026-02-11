package edu.cwru.passwordmanager.model;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;


public class PasswordModel {
    private ObservableList<Password> passwords = FXCollections.observableArrayList();

    // !!! DO NOT CHANGE - VERY IMPORTANT FOR GRADING !!!
    static private File passwordFile = new File("passwords.txt");

    static private String separator = "\t";

    static private String passwordFilePassword = "";
    static private byte [] passwordFileKey;
    static private byte [] passwordFileSalt;

    // TODO: You can set this to whatever you like to verify that the password the user entered is correct
    private static String verifyString = "cookies";

    private void loadPasswords() {
        // TODO: Replace with loading passwords from file, you will want to add them to the passwords list defined above
        // TODO: Tips: Use buffered reader, make sure you split on separator, make sure you decrypt password
        if (!passwordFile.exists()) {
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(passwordFile))) {
            // Read first line (salt and encrypted token)
            String firstLine = reader.readLine();
            if (firstLine == null) return;

            String[] parts = firstLine.split(separator);
            if (parts.length < 2) return;

            // Read salt and encrypted token from first line
            passwordFileSalt = Base64.getDecoder().decode(parts[0]);
            passwordFilePassword = parts[1];

            // Read all password entries (label + encrypted password)
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;  // Skip empty lines

                String[] passwordParts = line.split(separator);
                if (passwordParts.length == 2) {
                    String label = passwordParts[0];
                    String encryptedPassword = passwordParts[1];
                    
                    passwords.add(new Password(label, decryptPassword(encryptedPassword, passwordFileKey)));
                }
            }

        } catch (IOException e) {
            throw new RuntimeException("Failed to load passwords from file", e);
        }
    }

    public PasswordModel() {
        loadPasswords();
    }

    static public boolean passwordFileExists() {
        return passwordFile.exists();
    }

    static public void initializePasswordFile(String password) throws IOException {
        passwordFile.createNewFile();

        // TODO: Use password to create token and save in file with salt (TIP: Save these just like you would save password)
        passwordFileSalt = generateSalt();
        passwordFileKey = generateKey(password, passwordFileSalt);
        passwordFilePassword = encryptPassword(verifyString,passwordFileKey);

        BufferedWriter out = new BufferedWriter(new FileWriter(passwordFile));
        String saltString = Base64.getEncoder().encodeToString(passwordFileSalt);
        out.write(saltString + "\t"+ passwordFilePassword);
        out.newLine();
        out.close();

    }

    static public boolean verifyPassword(String password) {
        passwordFilePassword = password; // DO NOT CHANGE

        // TODO: Check first line and use salt to verify that you can decrypt the token using the password from the user
        // TODO: TIP !!! If you get an exception trying to decrypt, that also means they have the wrong passcode, return false!
        try (BufferedReader reader = new BufferedReader(new FileReader(passwordFile))) {
            String firstLine = reader.readLine();
            if (firstLine == null) return false;

            String[] parts = firstLine.split("\t");
            if (parts.length < 2) return false;

            passwordFileSalt = Base64.getDecoder().decode(parts[0]);
            String encryptedToken = parts[1];

            // Generate key
            passwordFileKey = generateKey(password, passwordFileSalt);
            // Try to decrypt the token
            try {
                String decrypted = decryptPassword(encryptedToken,passwordFileKey);

                // Check if decrypted token matches
                if (verifyString.equals(decrypted)) {
                    return true;
                }
            } catch (Exception e) {
                // Decryption failed = wrong password
                return false;
            }

        } catch (IOException e) {
            throw new RuntimeException("Failed to read password file", e);
        }

        return false;
    }

    public ObservableList<Password> getPasswords() {
        return passwords;
    }

    public void deletePassword(int index) {
        passwords.remove(index);

        // TODO: Remove it from file
        try {
            saveFile();
        }
        catch (IOException e) {
            throw new RuntimeException("File updating failed.", e);
        }
    }

    public void updatePassword(Password password, int index) {
        passwords.set(index, password);

        // TODO: Update the file with the new password information
        try {
            saveFile();
        }
        catch (IOException e) {
            throw new RuntimeException("File updating failed.", e);
        }
    }

    public void addPassword(Password password) {
        passwords.add(password);

        // TODO: Add the new password to the file
        try {
            saveFile();
        }
        catch (IOException e) {
            throw new RuntimeException("File updating failed.", e);
        }
    }

    // TODO: Tip: Break down each piece into individual methods, for example: generateSalt(), encryptPassword, generateKey(), saveFile, etc ...
    // TODO: Use these functions above, and it will make it easier! Once you know encryption, decryption, etc works, you just need to tie them in
    
    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte [] salt = new byte[16];
        random.nextBytes(salt);
        String saltString = Base64.getEncoder().encodeToString(salt);
        return saltString.getBytes();
    }

    public static byte[] generateKey(String password, byte[] salt) {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 600000, 256);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey privateKey = factory.generateSecret(spec);
            return privateKey.getEncoded();
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Key Generation failed", e);
        }
    }

    public static String encryptPassword(String password, byte[] masterKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(masterKey, "AES");

            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte [] encryptedData = cipher.doFinal(password.getBytes());
            String pwString = new String(Base64.getEncoder().encode(encryptedData));
            return pwString;
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public static String decryptPassword(String encrypted, byte[] masterKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(masterKey, "AES");

            cipher.init(Cipher.DECRYPT_MODE, key);

            byte [] decodedData = Base64.getDecoder().decode(encrypted);
            byte [] decryptedData = cipher.doFinal(decodedData);
            String decrypted = new String(decryptedData);
            return decrypted;
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    public void saveFile() throws IOException {
        List<String> lines = new ArrayList<>();
       

        lines.add(saltToString(passwordFileSalt) + "\t"+ passwordFilePassword);

        for (Password password : passwords) {
            lines.add(String.format("%s\t%s", 
                password.getLabel(), 
                encryptPassword(password.getPassword(), passwordFileKey)));
        }

        writeFile(lines);
    }

    public void writeFile(List<String> lines) throws IOException {
        Path filePath = passwordFile.toPath();
        
        Path parentDir = filePath.getParent();
        if (parentDir == null) {
            parentDir = Paths.get(".");
        }
        Path tempFile = Files.createTempFile(parentDir, "temp_", ".tmp");
        try {
            Files.write(tempFile, lines);
            Files.move(tempFile, filePath, 
                      StandardCopyOption.REPLACE_EXISTING, 
                      StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            Files.deleteIfExists(tempFile);
            throw e;
        }
    }

    public String saltToString(byte[] salt) {
        return Base64.getEncoder().encodeToString(passwordFileSalt);
    }

}
