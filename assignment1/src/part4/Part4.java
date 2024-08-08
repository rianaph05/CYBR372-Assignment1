
package part4;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Scanner;
import java.util.logging.Logger;

/**
 * @author Riana Pho
 *
 * java part4/Part4 ciphertext.enc -t 0
 * java part4/Part4 ciphertext.enc -t 1
 * java part4/Part4 ciphertext.enc -t 2
*/

public class Part4 {
    private static final Logger LOG = Logger.getLogger(Part4.class.getSimpleName());
    static String cipher = "AES/CBC/PKCS5PADDING";
    static String ALGORITHM = "AES";
    static String inFile = null;
    private static final int MAX_LENGTH = 6;
    static String foundPassword = null;
    static String decryptedString = null;
    static byte[] salt;
    static byte[] iv;
    static byte[] ciphertext;
    static char[] charSet;

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {

        // converting command line args to scanner
        StringBuilder str = new StringBuilder();
        System.out.println("--------------------------------------------");
        System.out.println(" ** COMMAND LINE **");
        for (String s : args) {
            str.append(s).append(" ");
            System.out.print(s + " ");
        }
        System.out.println("\n--------------------------------------------");

        String input = str.toString();
        Scanner command = new Scanner(input);

        // first arg is ciphertext file
        inFile = command.next();
        command.next();

        // second arg is mode for password specifications
        int number = command.nextInt();

        // pretty printing
        System.out.println(" ** CIPHERTEXT FILE **");
        System.out.println(inFile);
        System.out.println("--------------------------------------------");
        System.out.println(" ** PASSWORD PARAMETERS **");
        System.out.println("number:" + number);

        parseCipherText();

        // generate char [] based off password specifications
        charSet = initiateCharSet(number);

        // brute forcing password
        System.out.println("--------------------------------------------");
        System.out.println(" ** BRUTE FORCING... **");
        for (int length = 1; length <= MAX_LENGTH; length++) {
            generateAndTryPassword(charSet, new char[length], 0);
            if (foundPassword != null) {
                break;
            }
        }
        // if password is found
        if (foundPassword != null) {
            System.out.println("--------------------------------------------");
            System.out.println(" ** PASSWORD FOUND **");
            System.out.println("password: " + foundPassword);
            System.out.println("decrypted ciphertext: " + decryptedString);
            System.out.println("--------------------------------------------");
        } else {
            System.out.println("password not found");
        }
    }

    /**
     * Obtain salt, init vector and encrypted text from cipher text file
     * @throws IOException if an I/O error occurs during decryption process
     */
    public static void parseCipherText() throws IOException {
        Path path = Paths.get(inFile);
        byte[] fileContent = Files.readAllBytes(path);
        salt = Arrays.copyOfRange(fileContent, 0, 16);
        iv = Arrays.copyOfRange(fileContent, 16, 32);
        ciphertext = Arrays.copyOfRange(fileContent, 32, fileContent.length);
    }

    /**
     * Initiate char array with possible password characters
     * @param number password specifications
     * @return char [] containing possible characters
     */
    public static char[] initiateCharSet(int number){
        if (number == 0) {
            System.out.println("password is at most 6 characters long, composed only of lowercase letters");
            charSet = "abcdefghijklmnopqrstuvwxyz".toCharArray();
        } else if (number == 1) {
            System.out.println("password is at most 6 characters long, composed only of lowercase letters and numbers");
            charSet = "abcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
        } else if (number == 2) {
            System.out.println("password is at most 6 characters long, composed only of lowercase and uppercase letters");
            charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
        } else {
            System.out.println("invalid number provided");
            return null;
        }
        return charSet;
    }

    /**
     * Recursively generates and tries passwords
     * @param charSet char [] containing possible password characters
     * @param currentPassword char [] to store the current password being tested
     * @param position current position in the password array to set the next character
     * @throws NoSuchAlgorithmException if the algorithm for password decryption is not available
     * @throws InvalidKeySpecException if the specification for the key is invalid
     * @throws NoSuchPaddingException if the padding scheme for decryption is not available
     * @throws InvalidAlgorithmParameterException if the parameters for the decryption algorithm are invalid
     * @throws InvalidKeyException if the key used for decryption is invalid
     * @throws IOException if an I/O error occurs during decryption process
     */
    public static void generateAndTryPassword(char[] charSet, char[] currentPassword, int position) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        if (position == currentPassword.length) {
            return;
        }
        for (char c : charSet) {
            currentPassword[position] = c;
            String password = new String(currentPassword, 0, position + 1);
            System.out.println("attempt: " + password);
            if (decryptPassword(currentPassword, position + 1)) {
                foundPassword = password;
                return;
            }
            generateAndTryPassword(charSet, currentPassword, position + 1);
            if (foundPassword != null) {
                return;
            }
        }
    }

    /**
     * Decrypting password using specified length
     * @param password char [] of encrypted password to be decrypted
     * @param length length of the password to be used
     * @return true if the decryption is successful and the decrypted string contains mostly readable characters,
     *         false otherwise
     * @throws NoSuchAlgorithmException if the algorithm for password decryption is not available
     * @throws InvalidKeySpecException if the specification for the key is invalid
     * @throws NoSuchPaddingException if the padding scheme for decryption is not available
     * @throws InvalidAlgorithmParameterException if the parameters for the decryption algorithm are invalid
     * @throws InvalidKeyException if the key used for decryption is invalid
     * @throws IOException if an I/O error occurs during  decryption process
     */
    public static boolean decryptPassword(char[] password, int length) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        int count = 1000;
        PBEKeySpec pbeKeySpec = new PBEKeySpec(Arrays.copyOf(password, length), salt, count, 256);
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
        SecretKeySpec secretKeySpec = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);

        Cipher pbeCipher = Cipher.getInstance(cipher);
        pbeCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        try {
            byte[] decrypted = pbeCipher.doFinal(ciphertext);
            decryptedString = new String(decrypted);

            // check if string contains mostly readable chars
            for (char c : decryptedString.toCharArray()){
                if (c < 32 || c > 126){
                    return false;
                }
            }
            return true; // decryption succeeded
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            // decryption failed
            return false;
        }
    }
}

