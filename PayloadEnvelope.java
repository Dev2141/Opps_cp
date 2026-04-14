import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Unified payload format for text + file hiding.
 *
 * Layout:
 * [magic 4 bytes: STG1]
 * [type 1 byte: 0=text, 1=file]
 * [filenameLen 2 bytes unsigned]
 * [mimeLen 2 bytes unsigned]
 * [dataLen 8 bytes signed long, must be >= 0]
 * [filename UTF-8 bytes]
 * [mime UTF-8 bytes]
 * [data bytes]
 */
public final class PayloadEnvelope {

    private static final byte[] MAGIC = new byte[]{'S', 'T', 'G', '1'};
    private static final int TYPE_TEXT = 0;
    private static final int TYPE_FILE = 1;

    private PayloadEnvelope() {
    }

    public static byte[] fromText(String message) throws Exception {
        if (message == null) message = "";
        byte[] data = message.getBytes(StandardCharsets.UTF_8);
        return build(TYPE_TEXT, "", "text/plain", data);
    }

    public static byte[] fromFile(String fileName, String mimeType, byte[] fileBytes) throws Exception {
        if (fileName == null || fileName.isBlank()) fileName = "hidden.bin";
        if (mimeType == null || mimeType.isBlank()) mimeType = "application/octet-stream";
        if (fileBytes == null) fileBytes = new byte[0];
        return build(TYPE_FILE, fileName, mimeType, fileBytes);
    }

    public static boolean looksLikeEnvelope(byte[] raw) {
        return raw != null && raw.length >= 4 && raw[0] == MAGIC[0] && raw[1] == MAGIC[1]
                && raw[2] == MAGIC[2] && raw[3] == MAGIC[3];
    }

    public static DecodedPayload parse(byte[] raw) throws Exception {
        if (raw == null || raw.length < 17) {
            throw new Exception("Envelope is too small.");
        }

        DataInputStream in = new DataInputStream(new ByteArrayInputStream(raw));
        byte[] magic = new byte[4];
        in.readFully(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new Exception("Invalid payload magic.");
        }

        int type = in.readUnsignedByte();
        int fileNameLen = in.readUnsignedShort();
        int mimeLen = in.readUnsignedShort();
        long dataLenLong = in.readLong();
        if (dataLenLong < 0 || dataLenLong > Integer.MAX_VALUE) {
            throw new Exception("Invalid payload length.");
        }
        int dataLen = (int) dataLenLong;

        long remaining = raw.length - 17L;
        long needed = (long) fileNameLen + mimeLen + dataLen;
        if (needed > remaining) {
            throw new Exception("Envelope is truncated.");
        }

        byte[] fileNameBytes = new byte[fileNameLen];
        byte[] mimeBytes = new byte[mimeLen];
        byte[] dataBytes = new byte[dataLen];
        in.readFully(fileNameBytes);
        in.readFully(mimeBytes);
        in.readFully(dataBytes);

        String fileName = new String(fileNameBytes, StandardCharsets.UTF_8);
        String mimeType = new String(mimeBytes, StandardCharsets.UTF_8);

        if (type == TYPE_TEXT) {
            return DecodedPayload.text(dataBytes);
        }
        if (type == TYPE_FILE) {
            if (fileName.isBlank()) fileName = "hidden.bin";
            if (mimeType.isBlank()) mimeType = "application/octet-stream";
            return DecodedPayload.file(fileName, mimeType, dataBytes);
        }
        throw new Exception("Unsupported payload type: " + type);
    }

    private static byte[] build(int type, String fileName, String mimeType, byte[] data) throws Exception {
        byte[] fileNameBytes = fileName.getBytes(StandardCharsets.UTF_8);
        byte[] mimeBytes = mimeType.getBytes(StandardCharsets.UTF_8);

        if (fileNameBytes.length > 0xFFFF) {
            throw new Exception("File name too long.");
        }
        if (mimeBytes.length > 0xFFFF) {
            throw new Exception("MIME type too long.");
        }

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bout);
        out.write(MAGIC);
        out.writeByte(type);
        out.writeShort(fileNameBytes.length);
        out.writeShort(mimeBytes.length);
        out.writeLong(data.length);
        out.write(fileNameBytes);
        out.write(mimeBytes);
        out.write(data);
        out.flush();
        return bout.toByteArray();
    }

    public static final class DecodedPayload {
        public final boolean isFile;
        public final String fileName;
        public final String mimeType;
        public final byte[] data;

        private DecodedPayload(boolean isFile, String fileName, String mimeType, byte[] data) {
            this.isFile = isFile;
            this.fileName = fileName;
            this.mimeType = mimeType;
            this.data = data;
        }

        public static DecodedPayload text(byte[] data) {
            return new DecodedPayload(false, "", "text/plain", data);
        }

        public static DecodedPayload file(String fileName, String mimeType, byte[] data) {
            return new DecodedPayload(true, fileName, mimeType, data);
        }

        public String asText() {
            return new String(data, StandardCharsets.UTF_8);
        }
    }
}
