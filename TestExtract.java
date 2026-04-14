import javax.crypto.*;
import javax.crypto.spec.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.imageio.ImageIO;

/**
 * Quick test: extract + decrypt the hidden message from a stego image.
 *
 * Usage:
 *   javac TestExtract.java
 *   java TestExtract stego_output.png yourPassword
 */
public class TestExtract {

    // Must match EncryptionService constants
    private static final byte[] SALT   = "STEG_SALT_2025".getBytes();
    private static final int    ITER   = 65536;
    private static final int    IV_LEN = 12;

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: java TestExtract <stego_image.png> <password>");
            return;
        }
        File imgFile = new File(args[0]);
        char[] password = args[1].toCharArray();

        // 1. Load stego image
        BufferedImage img = ImageIO.read(imgFile);
        if (img == null) { System.out.println("Cannot read image."); return; }

        // 2. Extract LSB bits → reconstruct bytes
        int totalPixelChannels = img.getWidth() * img.getHeight() * 3;
        byte[] raw = new byte[totalPixelChannels / 8];
        int bitIdx = 0;
        outer:
        for (int y = 0; y < img.getHeight(); y++) {
            for (int x = 0; x < img.getWidth(); x++) {
                int rgb = img.getRGB(x, y);
                int[] channels = {(rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF};
                for (int ch : channels) {
                    if (bitIdx >= raw.length * 8) break outer;
                    raw[bitIdx / 8] |= (byte)((ch & 1) << (7 - bitIdx % 8));
                    bitIdx++;
                }
            }
        }

        // 3. Read the 4-byte length header
        int dataLen = ((raw[0] & 0xFF) << 24) | ((raw[1] & 0xFF) << 16)
                    | ((raw[2] & 0xFF) <<  8) |  (raw[3] & 0xFF);
        System.out.println("Hidden data length (bytes): " + dataLen);

        if (dataLen <= 0 || dataLen > raw.length - 4) {
            System.out.println("ERROR: Invalid length. Image may not contain hidden data.");
            return;
        }

        // 4. Copy out the cipher payload
        byte[] cipherPayload = new byte[dataLen];
        System.arraycopy(raw, 4, cipherPayload, 0, dataLen);

        // 5. Decrypt exactly as EncryptionService does
        SecretKey key = deriveKey(password);
        byte[] iv = new byte[IV_LEN];
        System.arraycopy(cipherPayload, 0, iv, 0, IV_LEN);
        byte[] cipherText = new byte[cipherPayload.length - IV_LEN];
        System.arraycopy(cipherPayload, IV_LEN, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] plain = cipher.doFinal(cipherText);

        System.out.println("✅ Decrypted message: " + new String(plain, StandardCharsets.UTF_8));
    }

    private static SecretKey deriveKey(char[] password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] raw = f.generateSecret(new PBEKeySpec(password, SALT, ITER, 256)).getEncoded();
        return new SecretKeySpec(raw, "AES");
    }
}
