package part3;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Riana Pho
 *
 * java part3/Part3
 */

public class Part3 {
    private static final Logger LOG = Logger.getLogger(part3.Part3.class.getSimpleName());
    private static final String ALGORITHM = "AES";

    // -----------------------------------------
    // Variables
    static String mode = "CBC";
    static String cipher = "AES/"+mode+"/PKCS5PADDING";
    // PKCS5PADDING
    static int KEY_LENGTH = 32; // in bytes
    // -----------------------------------------

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {

        System.out.println("--------------------------------------------");
        System.out.println(" ** GENERATING SECRET KEYS **");
        byte[] key1 = generateSecretKey();
        byte[] key2 = generateSecretKey();
        byte[] key3 = generateSecretKey();
        System.out.println("--------------------------------------------");

        System.out.println(" ** GENERATING INIT VECTORS **");
        byte[] initVec1 = generateInitVector();
        byte[] initVec2 = generateInitVector();
        byte[] initVec3 = generateInitVector();
        System.out.println("--------------------------------------------");

        String plaintext = "plaintext.txt";

        String encrypted1 = "encrypted1.enc";
        String encrypted2 = "encrypted2.enc";
        String encrypted3 = "encrypted3.enc";

        String decrypted1 = "decrypted1.dec";
        String decrypted2 = "decrypted2.dec";
        String decrypted3 = "decrypted3.dec";

        if (mode.equals("GCM")) {
            cipher = "AES/GCM/NoPadding";
        } else if (mode.equals("CTR")) {
            cipher = "AES/CTR/NoPadding";
        } else {
            cipher = "AES/" + mode + "/PKCS5PADDING";
        }

        System.out.println(" ** AES MODE OF OPERATION **\n" + cipher);
        System.out.println("--------------------------------------------");

        System.out.println("** TEST 1 **");
        System.out.println("--------------------------------------------");
        long encrypt1 = encrypt(key1, initVec1, plaintext, encrypted1);
        long decrypt1 = decrypt(key1, initVec1, encrypted1, decrypted1);

        System.out.println("--------------------------------------------");
        System.out.println("** TEST 2 **");
        System.out.println("--------------------------------------------");
        long encrypt2 = encrypt(key2, initVec2, plaintext, encrypted2);
        long decrypt2 = decrypt(key2, initVec2, encrypted2, decrypted2);
        System.out.println("--------------------------------------------");

        System.out.println("** TEST 3 **");
        System.out.println("--------------------------------------------");
        long encrypt3 = encrypt(key3, initVec3, plaintext, encrypted3);
        long decrypt3 = decrypt(key3, initVec3, encrypted3, decrypted3);
        System.out.println("--------------------------------------------");

        System.out.println(" ** FINAL RESULTS FOR " + mode + " mode, " + KEY_LENGTH*8 + " bits key length ** ");
        System.out.println("--------------------------------------------");
        System.out.println("encrypt 1: " + encrypt1);
        System.out.println("encrypt 2: " + encrypt2);
        System.out.println("encrypt 3: " + encrypt3);

        long averageEncrypt = (encrypt1+encrypt2+encrypt3)/3;
        System.out.println("average: " + averageEncrypt + "\n");

        System.out.println("decrypt 1: " + decrypt1);
        System.out.println("decrypt 2: " + decrypt2);
        System.out.println("decrypt 3: " + decrypt3);

        long averageDecrypt = (decrypt1+decrypt2+decrypt3)/3;
        System.out.println("average: " + averageDecrypt + "\n");

    }

    /**
     * Generating secret key if encrypting and key is not specified
     * Stored in key
     * Saved to file key.base64
     * Encoded in base64
     */
    public static byte[] generateSecretKey() {
        SecureRandom sr = new SecureRandom();
        byte[] sKey = new byte[KEY_LENGTH];
        sr.nextBytes(sKey); // 16 bytes secret key
        System.out.println("generated random key: " + sKey);
        return sKey;
    }

    /**
     * Generating initialization vector if encrypting and is not specified
     * Stored in iv
     * Saved to file iv.base64
     * Encoded in base64
     */
    public static byte[] generateInitVector() {
        SecureRandom sr = new SecureRandom();
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV
        System.out.println("generated random init vector: " + initVector);
        return initVector;
    }

    /**
     * Encrypting inFile with specified mode, key and initialization vector
     * saved to outFile
     * @throws NoSuchPaddingException if the padding scheme for decryption is not available
     * @throws NoSuchAlgorithmException if the algorithm for password decryption is not available
     * @throws InvalidAlgorithmParameterException if the parameters for the decryption algorithm are invalid
     * @throws InvalidKeyException if the key used for decryption is invalid
     */
    public static long encrypt(byte[] key, byte[] iv, String inFile, String outFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {

        System.out.println(" ** ENCRYPTING STATISTICS **");

        IvParameterSpec initVec = new IvParameterSpec(iv);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

        Cipher ciph = Cipher.getInstance(cipher);

        if (mode.equals("GCM")) {
            GCMParameterSpec gcmParams = new GCMParameterSpec(128, iv);
            ciph.init(Cipher.ENCRYPT_MODE, skeySpec, gcmParams);
        } else if (mode.equals("ECB")) {
            ciph.init(Cipher.ENCRYPT_MODE, skeySpec);
        } else if (mode.equals("CTR")){
            ciph.init(Cipher.ENCRYPT_MODE, skeySpec, initVec);
        }
        else {
            ciph.init(Cipher.ENCRYPT_MODE, skeySpec, initVec);
        }

        long start = System.nanoTime();

        try (InputStream fin = new FileInputStream(inFile);
             OutputStream fout = Files.newOutputStream(Path.of(outFile));
             CipherOutputStream cipherOut = new CipherOutputStream(fout, ciph) {
             }) {
            final byte[] bytes = new byte[1024];
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }

        long finish = System.nanoTime();
        long timeElapsed = finish - start;

        LOG.info("Encryption finished, saved at " + outFile);
        System.out.println("time: " + timeElapsed + " nanoseconds");
        return timeElapsed;

    }

    /**
     * Decrypting inFile with specified mode, key and initialization vector
     * saved to outFile
     * @throws NoSuchPaddingException if the padding scheme for decryption is not available
     * @throws NoSuchAlgorithmException if the algorithm for password decryption is not available
     * @throws InvalidAlgorithmParameterException if the parameters for the decryption algorithm are invalid
     * @throws InvalidKeyException if the key used for decryption is invalid
     */
    public static long decrypt(byte[] key, byte[] iv, String inFile, String outFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        System.out.println("\n ** DECRYPTING STATISTICS **");

        IvParameterSpec initVec = new IvParameterSpec(iv);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

        Cipher ciph = Cipher.getInstance(cipher);

        // initialise cipher dependent on mode and correlating parameters
        if (mode.equals("GCM")) {
            GCMParameterSpec gcmParams = new GCMParameterSpec(128, iv);
            ciph.init(Cipher.DECRYPT_MODE, skeySpec, gcmParams);
        } else if (mode.equals("ECB")) {
            ciph.init(Cipher.DECRYPT_MODE, skeySpec);
        } else if (mode.equals("CTR")){
            ciph.init(Cipher.DECRYPT_MODE, skeySpec, initVec);
        }
        else {
            ciph.init(Cipher.DECRYPT_MODE, skeySpec, initVec);
        }

        long start = System.nanoTime();

        try (InputStream encryptedData = Files.newInputStream(Path.of(inFile));
             CipherInputStream decryptStream = new CipherInputStream(encryptedData, ciph);
             OutputStream decryptedOut = Files.newOutputStream(Path.of(outFile))){
            final byte[] bytes = new byte[1024];
            for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(Part3.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }

        long finish = System.nanoTime();
        long timeElapsed = finish - start;

        LOG.info("Decryption complete, open " + outFile);
        System.out.println("time: " + timeElapsed + " nanoseconds");
        return timeElapsed;
    }
}