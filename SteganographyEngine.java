import java.awt.image.BufferedImage;

/** Module 4 – LSB Steganography Embedding */
public class SteganographyEngine {

    /**
     * Embed 'data' into a copy of 'carrier' using LSB steganography.
     * Format stored in image: [4-byte length header][data bytes]
     */
    public static BufferedImage embed(BufferedImage carrier, byte[] data) throws Exception {
        int capacity = (carrier.getWidth() * carrier.getHeight() * 3) / 8;
        if (data.length + 4 > capacity)
            throw new Exception("Image too small. Need " + (data.length + 4) +
                                " bytes but capacity is " + capacity + " bytes.");

        // Deep-copy the carrier so original is untouched
        BufferedImage stego = new BufferedImage(
            carrier.getWidth(), carrier.getHeight(), BufferedImage.TYPE_INT_RGB);
        stego.getGraphics().drawImage(carrier, 0, 0, null);

        // Build full bit stream: 32-bit length header + data bits
        byte[] payload = new byte[4 + data.length];
        int len = data.length;
        payload[0] = (byte)(len >> 24);
        payload[1] = (byte)(len >> 16);
        payload[2] = (byte)(len >>  8);
        payload[3] = (byte)(len);
        System.arraycopy(data, 0, payload, 4, data.length);

        // Write bits into pixel LSBs (R, G, B channels, row-major)
        int bitIdx = 0;
        int totalBits = payload.length * 8;
        outer:
        for (int y = 0; y < stego.getHeight(); y++) {
            for (int x = 0; x < stego.getWidth(); x++) {
                int rgb = stego.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >>  8) & 0xFF;
                int b =  rgb        & 0xFF;

                if (bitIdx < totalBits) r = setBit(r, getBit(payload, bitIdx++));
                if (bitIdx < totalBits) g = setBit(g, getBit(payload, bitIdx++));
                if (bitIdx < totalBits) b = setBit(b, getBit(payload, bitIdx++));

                stego.setRGB(x, y, (r << 16) | (g << 8) | b);
                if (bitIdx >= totalBits) break outer;
            }
        }
        return stego;
    }

    /**
     * Extract hidden bytes from a stego image produced by embed().
     * Reads LSBs of R,G,B channels → 4-byte length header → payload.
     */
    public static byte[] extract(BufferedImage img) throws Exception {
        // Read enough bits for header + maximum possible payload
        int totalBits = img.getWidth() * img.getHeight() * 3;
        byte[] raw = new byte[totalBits / 8];
        int bitIdx = 0;
        outer:
        for (int y = 0; y < img.getHeight(); y++) {
            for (int x = 0; x < img.getWidth(); x++) {
                int rgb = img.getRGB(x, y);
                int[] ch = {(rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF};
                for (int c : ch) {
                    if (bitIdx >= raw.length * 8) break outer;
                    raw[bitIdx / 8] |= (byte)((c & 1) << (7 - bitIdx % 8));
                    bitIdx++;
                }
            }
        }
        // Decode 4-byte length header
        int dataLen = ((raw[0] & 0xFF) << 24) | ((raw[1] & 0xFF) << 16)
                    | ((raw[2] & 0xFF) <<  8) |  (raw[3] & 0xFF);
        if (dataLen <= 0 || dataLen > raw.length - 4)
            throw new Exception("No hidden data found in this image.");

        byte[] payload = new byte[dataLen];
        System.arraycopy(raw, 4, payload, 0, dataLen);
        return payload;
    }

    // ── Helpers ──────────────────────────────────────────────────────
    private static int getBit(byte[] arr, int n) {
        return (arr[n / 8] >> (7 - n % 8)) & 1;
    }

    private static int setBit(int value, int bit) {
        return (value & 0xFE) | bit;
    }
}
