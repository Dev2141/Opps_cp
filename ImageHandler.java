import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

/** Module 2 – Image Handling */
public class ImageHandler {

    /** Load any PNG / BMP / JPG into a BufferedImage. */
    public static BufferedImage load(File f) throws IOException {
        BufferedImage img = ImageIO.read(f);
        if (img == null) throw new IOException("Unsupported image format.");
        return img;
    }

    /**
     * Maximum bytes that can be hidden:
     *   width × height × 3 channels × 1 LSB / 8 bits
     */
    public static int capacityBytes(BufferedImage img) {
        return (img.getWidth() * img.getHeight() * 3) / 8;
    }

    /** Save the stego image as a lossless PNG. */
    public static void savePNG(BufferedImage img, File dest) throws IOException {
        if (!ImageIO.write(img, "PNG", dest))
            throw new IOException("PNG write failed.");
    }
}
