import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class EncryptionService {

    private static final byte[] SALT = "STEG_SALT_2025".getBytes();
    private static final int    ITER = 65536;
    private static final int    IV_LEN = 12;

    /** Derive a 256-bit AES key from the given password. */
    private static SecretKey deriveKey(char[] password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password, SALT, ITER, 256);
        byte[] raw = f.generateSecret(spec).getEncoded();
        return new SecretKeySpec(raw, "AES");
    }
    
    /**
     * Encrypt plaintext with AES-256-GCM.
     * Returns: IV (12 bytes) || ciphertext
     */
    public static byte[] encrypt(char[] password, byte[] plaintext) throws Exception {
        SecretKey key = deriveKey(password);
        byte[] iv = new byte[IV_LEN];
        new SecureRandom().nextBytes(iv);
        

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(plaintext);

        byte[] out = new byte[IV_LEN + ct.length];
        System.arraycopy(iv, 0, out, 0,      IV_LEN);
        System.arraycopy(ct, 0, out, IV_LEN, ct.length);
        return out;
    }

    /**
     * Decrypt output produced by encrypt().
     * Input format: IV (12 bytes) || ciphertext
     */
    public static byte[] decrypt(char[] password, byte[] data) throws Exception {
        SecretKey key = deriveKey(password);
        byte[] iv = new byte[IV_LEN];
        byte[] ct = new byte[data.length - IV_LEN];
        System.arraycopy(data, 0,      iv, 0, IV_LEN);
        System.arraycopy(data, IV_LEN, ct, 0, ct.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(ct);
    }
}
