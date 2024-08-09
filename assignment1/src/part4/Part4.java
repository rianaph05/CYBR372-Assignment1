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
    private static final char[] ZERO_CHARS = "abcdefghijklmnopqrstuvwxyz".toCharArray();
    private static final char[] ONE_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
    private static final char[] TWO_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
    private static final int MAX_LENGTH = 6;
    static String foundPassword = null;
    static byte[] salt;
    static byte[] iv;
    static byte[] ciphertext;

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {

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

        inFile = command.next();
        command.next();
        int number = command.nextInt();

        System.out.println(" ** CIPHERTEXT FILE **");
        System.out.println(inFile);
        System.out.println("--------------------------------------------");

        System.out.println(" ** PASSWORD PARAMETERS **");
        System.out.println("number:" + number);

        Path path = Paths.get(inFile);
        byte[] fileContent = Files.readAllBytes(path);
        salt = Arrays.copyOfRange(fileContent, 0, 16);
        iv = Arrays.copyOfRange(fileContent, 16, 32);
        ciphertext = Arrays.copyOfRange(fileContent, 32, fileContent.length);

        char[] charSet;
        if (number == 0) {
            System.out.println("password is at most 6 characters long, composed only of lowercase letters");
            charSet = ZERO_CHARS;
        } else if (number == 1) {
            System.out.println("password is at most 6 characters long, composed only of lowercase letters and numbers");
            charSet = ONE_CHARS;
        } else if (number == 2) {
            System.out.println("password is at most 6 characters long, composed only of lowercase and uppercase letters");
            charSet = TWO_CHARS;
        } else {
            System.out.println("invalid number provided");
            return;
        }

        System.out.println("--------------------------------------------");
        System.out.println(" ** BRUTE FORCING... **");
        for (int length = 1; length <= MAX_LENGTH; length++) {
            generateAndTryPassword(charSet, new char[length], 0);
            if (foundPassword != null) {
                break;
            }
        }
        if (foundPassword != null) {
            System.out.println("password found: " + foundPassword);
        } else {
            System.out.println("password not found");
        }
    }

    private static void generateAndTryPassword(char[] charSet, char[] currentPassword, int position) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
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
            String decryptedString = new String(decrypted);
            System.out.println("decrypted ciphertext: " + decryptedString);
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
