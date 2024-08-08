package part2;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * @author Riana Pho
 *
 * java part2/Part2 enc --pass "my password" -i plaintext.txt -o ciphertext.enc
 * java part2/Part2 dec -p "my password" -i ciphertext.enc -o plaintext.txt
 */

public class Part2 {
    private static final Logger LOG = Logger.getLogger(Part2.class.getSimpleName());
    private static final String ALGORITHM = "AES";
    static final Pattern KEY = Pattern.compile("-k|--key-file");
    static final Pattern INIT_VECTOR = Pattern.compile("-iv|--initialisation-vector");
    static final Pattern AES_MODE = Pattern.compile("-m|--mode");
    static final Pattern INPUT_FILE = Pattern.compile("-i|--input-file");
    static final Pattern OUTPUT_FILE = Pattern.compile("-o|--output-file");
    static final Pattern PASSWORD = Pattern.compile("-p|--pass");

    static String encryptionOp = null;
    static byte[] key = null;
    static byte[] iv = null;
    static String mode = "CBC";
    static String cipher = "AES/CBC/PKCS5PADDING";
    static String inFile = null;
    static String outFile = null;
    static char[] password = null;

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

        // first arg is enc or dec
        encryptionOp = command.next();

        // identify following args
        while (command.hasNext()) {
            checkCommand(command);
        }

        // generate secret key if not found and encrypting
        if (password == null && key == null && encryptionOp.equals("enc")) {
            generateSecretKey();
        }
        // generate init vector if not found and encrypting
        if (password == null && iv == null && encryptionOp.equals("enc")) {
            generateInitVector();
        }
        // generate out file if not found
        if (outFile == null) {
            generateOutputFile();
        }
        // encrypt based on operation
        // if a password is found, encrypt with password
        if (encryptionOp.equals("enc")) {
            if (password != null){
                encryptPassword();
            }
            else{
                encrypt();
            }
        }
        // decrypt based on operation
        // if a password is found, decrypt with password
        else if (encryptionOp.equals("dec")) {
            if (password != null){
                decryptPassword();
            }
            else {
                decrypt();
            }
        }
    }

    /**
     * Checking command line for user specification
     * and sending to function to handle
     * @param command Scanner containing command line
     */
    public static void checkCommand(Scanner command) {
        if (command.hasNext(KEY)) {
            setSecretKey(command);
        } else if (command.hasNext(INIT_VECTOR)) {
            setInitVector(command);
        } else if (command.hasNext(AES_MODE)) {
            setAesMode(command);
        } else if (command.hasNext(INPUT_FILE)) {
            setInputFile(command);
        } else if (command.hasNext(OUTPUT_FILE)) {
            setOutputFile(command);
        } else if (command.hasNext(PASSWORD)){
            setPassword(command);
        }
    }

    /**
     * Setting key based with proceeding "-k | --key"
     * Stored in key
     * @param command Scanner containing command line
     */
    public static void setSecretKey(Scanner command) {
        String secretKey = command.findInLine(KEY);
        if (secretKey != null) {
            key = pathToByteArray(command.next());
        }
        System.out.println(" ** SECRET KEY **\n" + key);
        System.out.println("--------------------------------------------");
    }

    /**
     * Setting initialization vector with value proceeding "-iv | --initialisation-vector"
     * Stored in iv
     * @param command Scanner containing command line
     */
    public static void setInitVector(Scanner command) {
        String initVector = command.findInLine(INIT_VECTOR);
        if (initVector != null) {
            iv = pathToByteArray(command.next());
        }
        System.out.println(" ** INITIALISATION VECTOR **\n" + iv);
        System.out.println("--------------------------------------------");
    }

    /**
     * Setting cipher with value proceeding "-m | --mode"
     * Stored in cipher
     * @param command Scanner containing command line
     */
    public static void setAesMode(Scanner command) {
        String aesMode = command.findInLine(AES_MODE);
        if (aesMode != null) {
            mode = command.next();
            if (mode.equals("GCM")) {
                cipher = "AES/GCM/NoPadding";
            } else if (mode.equals("CTR")) {
                cipher = "AES/CTR/NoPadding";
            } else {
                cipher = "AES/" + mode + "/PKCS5PADDING";
            }
        }

        System.out.println(" ** AES MODE OF OPERATION **\n" + cipher);
        System.out.println("--------------------------------------------");
    }

    /**
     * Setting input file with value proceeding "-i | --input-file"
     * Stored in inFile
     * @param command Scanner containing command line
     */
    public static void setInputFile(Scanner command) {
        String in = command.findInLine(INPUT_FILE);
        if (in != null) {
            inFile = command.next();
            System.out.println(" ** INPUT FILE **\n" + inFile);
            System.out.println("--------------------------------------------");
        }
    }

    /**
     * Setting output file with value proceeding "-o | --output-file"
     * Stored in outFile
     * Appropriate extension appended or amended
     * @param command Scanner containing command line
     */
    public static void setOutputFile(Scanner command) {
        String out = command.findInLine(OUTPUT_FILE);
        if (out != null && encryptionOp.equals("enc")) {
            outFile = command.next();
            if (!outFile.contains("enc")) {
                outFile = outFile + ".enc";
            }
        } else if (out != null && encryptionOp.equals("dec")) {
            outFile = command.next();
            if (outFile.contains("enc")) {
                outFile = outFile.replace(".enc", ".dec");
            } else {
                outFile = outFile + ".dec";
            }
        }
        System.out.println(" ** OUTPUT FILE **\n" + outFile);
        System.out.println("--------------------------------------------");
    }

    /**
     * Setting password with value preceeding "-p | --pass" and found within
     * quotation marks
     * Stored in password
     * @param command Scanner containing command line
     */
    public static void setPassword(Scanner command){
        String pass = command.findInLine(PASSWORD);
        command.useDelimiter("-");
        if (pass != null) {
            String p = command.next();
            p = p.trim();
            password = p.toCharArray();
            command.reset();
        }
        System.out.println(" ** PASSWORD **\n" + Arrays.toString(password));
        System.out.println("--------------------------------------------");
    }

    /**
     * Generating outputFile if outFile is not specified
     * Appropriate extension appended or amended
     */
    public static void generateOutputFile() {
        if (encryptionOp.equals("enc")) {
            outFile = inFile + ".enc";
        } else if (encryptionOp.equals("dec")) {
            if (inFile.contains("enc")) {
                outFile = inFile.replace(".enc", ".dec");
            } else {
                outFile = inFile + ".dec";
            }
        }
        System.out.println(" ** OUTPUT FILE **\n" + outFile);
        System.out.println("--------------------------------------------");
    }

    /**
     * Generating secret key if encrypting and key is not specified
     * Stored in key
     * Saved to file key.base64
     * Encoded in base64
     */
    public static void generateSecretKey() {
        SecureRandom sr = new SecureRandom();
        byte[] sKey = new byte[16];
        sr.nextBytes(sKey); // 128-bit key
        System.out.println(" ** GENERATE SECRET KEY **");
        System.out.println("generated random key: " + sKey);
        key = sKey;
        String filename = "key.base64";
        File keyFile = new File(filename);
        encode64(sKey, keyFile);
    }

    /**
     * Generating initialization vector if encrypting and is not specified
     * Stored in iv
     * Saved to file iv.base64
     * Encoded in base64
     */
    public static void generateInitVector() {
        SecureRandom sr = new SecureRandom();
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV
        System.out.println(" ** GENERATE INITIALISATION VECTOR **");
        System.out.println("generated random init vector: " + initVector);
        iv = initVector;
        String filename = "iv.base64";
        File ivFile = new File(filename);
        encode64(initVector, ivFile);
    }

    /**
     * Encrypting inFile with specified mode, key and initialization vector
     * saved to outFile
     * @throws NoSuchPaddingException if the padding scheme for decryption is not available
     * @throws NoSuchAlgorithmException if the algorithm for password decryption is not available
     * @throws InvalidAlgorithmParameterException if the parameters for the decryption algorithm are invalid
     * @throws InvalidKeyException if the key used for decryption is invalid
     */
    public static void encrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {

        System.out.println(" ** ENCRYPTING **");

        IvParameterSpec initVec = new IvParameterSpec(iv);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

        Cipher ciph = Cipher.getInstance(cipher);

        // initialise cipher dependent on mode and correlating parameters
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

        LOG.info("Encryption finished, saved at " + outFile);

        System.out.println("--------------------------------------------");
    }

    /**
     * Decrypting inFile with specified mode, key and initialization vector
     * saved to outFile
     * @throws NoSuchPaddingException if the padding scheme for decryption is not available
     * @throws NoSuchAlgorithmException if the algorithm for password decryption is not available
     * @throws InvalidAlgorithmParameterException if the parameters for the decryption algorithm are invalid
     * @throws InvalidKeyException if the key used for decryption is invalid
     */
    public static void decrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        System.out.println(" ** DECRYPTING **");

        IvParameterSpec initVec = new IvParameterSpec(iv);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

        Cipher ciph = Cipher.getInstance(cipher);

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

        try (InputStream encryptedData = Files.newInputStream(Path.of(inFile));
             CipherInputStream decryptStream = new CipherInputStream(encryptedData, ciph);
             OutputStream decryptedOut = Files.newOutputStream(Path.of(outFile))) {
            final byte[] bytes = new byte[1024];
            for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(Part2.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }

        LOG.info("Decryption complete, open " + outFile);

        System.out.println("--------------------------------------------");
    }

    /**
     * Encrypting inFile with specified password
     * saved to outFile
     * @throws NoSuchAlgorithmException if the algorithm for password decryption is not available
     * @throws InvalidKeySpecException if the specification for the key is invalid
     * @throws NoSuchPaddingException if the padding scheme for decryption is not available
     * @throws InvalidAlgorithmParameterException if the parameters for the decryption algorithm are invalid
     * @throws InvalidKeyException if the key used for decryption is invalid
     */
    public static void encryptPassword() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        System.out.println(" ** GENERATE SECRET KEY WITH PASSWORD **");

        PBEKeySpec pbeKeySpec;
        SecretKeyFactory keyFac;

        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        System.out.println("salt: " + Base64.getEncoder().encodeToString(salt));

        int count = 1000;
        String ALGORITHM = "AES";
        String ciph = "AES/CBC/PKCS5Padding";

        pbeKeySpec = new PBEKeySpec(password, salt, count, 256);
        keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
        SecretKeySpec secretKeySpec = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);

        System.out.println("secret key from password: " + Base64.getEncoder().encodeToString(pbeKey.getEncoded()));
        System.out.println("--------------------------------------------");

        Cipher pbeCipher = Cipher.getInstance(ciph);
        pbeCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        byte[] iv = pbeCipher.getIV();

        System.out.println(" ** GENERATE INIT VECTOR WITH PASSWORD **");
        System.out.println("iv: " + Base64.getEncoder().encodeToString(iv));
        System.out.println("--------------------------------------------");
        System.out.println(" ** ENCRYPTING WITH SECRET KEY FROM PASSWORD **");

        try (InputStream fin = new FileInputStream(inFile);
             OutputStream fout = Files.newOutputStream(Path.of(outFile));
             CipherOutputStream cipherOut = new CipherOutputStream(fout, pbeCipher)) {
            final byte[] bytes = new byte[1024];
            fout.write(salt);
            fout.write(iv);
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        LOG.info("Encryption complete, open " + outFile);
        System.out.println("--------------------------------------------");
    }

    /**
     * Decrypting inFile with specified password
     * saved to outFile
     * @throws NoSuchAlgorithmException if the algorithm for password decryption is not available
     * @throws InvalidKeySpecException if the specification for the key is invalid
     * @throws NoSuchPaddingException if the padding scheme for decryption is not available
     * @throws InvalidAlgorithmParameterException if the parameters for the decryption algorithm are invalid
     * @throws InvalidKeyException if the key used for decryption is invalid
     */
    public static void decryptPassword() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        System.out.println(" ** GENERATE SECRET KEY WITH PASSWORD **");

        PBEKeySpec pbeKeySpec;
        SecretKeyFactory keyFac;

        int count = 1000;
        String ALGORITHM = "AES";
        String ciph = "AES/CBC/PKCS5Padding";

        Path path = Paths.get(inFile);
        byte[] fileContent = Files.readAllBytes(path);
        byte[] salt = Arrays.copyOfRange(fileContent, 0, 16);
        byte[] iv = Arrays.copyOfRange(fileContent, 16, 32);

        System.out.println("salt: " + Base64.getEncoder().encodeToString(salt));
        System.out.println("iv: " + Base64.getEncoder().encodeToString(iv));

        pbeKeySpec = new PBEKeySpec(password, salt, count, 256);
        keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
        SecretKeySpec secretKeySpec = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);

        System.out.println("secret key from password: " + Base64.getEncoder().encodeToString(pbeKey.getEncoded()));
        System.out.println("--------------------------------------------");

        Cipher pbeCipher = Cipher.getInstance(ciph);
        pbeCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        System.out.println(" ** DECRYPTING WITH SECRET KEY FROM PASSWORD **");

        try (InputStream fin = new FileInputStream(inFile);
             CipherInputStream cipherIn = new CipherInputStream(fin, pbeCipher);
             OutputStream fout = Files.newOutputStream(Path.of(outFile))){
            final byte[] bytes = new byte[1024];
            fin.skip(32); // skip the salt and IV
            for (int length = cipherIn.read(bytes); length != -1; length = cipherIn.read(bytes)) {
                fout.write(bytes, 0, length);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        LOG.info("Decryption complete, open " + outFile);
        System.out.println("--------------------------------------------");
    }

    /**
     * Converting path to encoded base64 byte array
     * @param pathName path to file containing string to be encoded
     * @return byte[] encoded in base64
     */
    public static byte[] pathToByteArray(String pathName) {
        System.out.println("reading path: " + pathName);
        Path path = Paths.get(pathName);
        try {
            byte[] input = Files.readAllBytes(path);
            return Base64.getDecoder().decode(input);
        } catch (IOException e) {
            System.out.println("error converting path to byte array");
            return null;
        }
    }

    /**
     * Encoding byte[] in base64 and saving to file
     * @param toEncode byte[] to encode
     * @param file file to save encoded byte[] to
     */
    public static void encode64(byte[] toEncode, File file) {
        byte[] encoded64 = Base64.getEncoder().encode(toEncode);

        try (FileOutputStream outputStream = new FileOutputStream(file)) {
            outputStream.write(encoded64);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.println("saved to file: " + file);
        System.out.println("--------------------------------------------");
    }
}