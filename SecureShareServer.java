import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Lightweight local sharing API for stego images.
 *
 * Start:
 *   javac SecureShareServer.java
 *   java SecureShareServer
 */
public class SecureShareServer {

    private static final int DEFAULT_PORT = 8088;
    private static final int PBKDF2_ITER = 120_000;
    private static final int PBKDF2_BITS = 256;
    private static final Pattern MAILBOX_ID_RE = Pattern.compile("^[a-zA-Z0-9_-]{3,32}$");
    private static final Pattern MESSAGE_ID_RE = Pattern.compile("^[a-fA-F0-9\\-]{8,64}$");

    private final HttpServer server;
    private final Path root;

    public SecureShareServer(int port, Path rootDir) throws IOException {
        this.root = rootDir.toAbsolutePath().normalize();
        Files.createDirectories(mailboxesRoot());

        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/health", withCors(this::handleHealth));
        server.createContext("/api/mailbox/register", withCors(this::handleRegister));
        server.createContext("/api/message/send", withCors(this::handleSend));
        server.createContext("/api/message/list", withCors(this::handleList));
        server.createContext("/api/message/download", withCors(this::handleDownload));
        server.createContext("/api/message/delete", withCors(this::handleDelete));
        server.setExecutor(null);
    }

    public static void main(String[] args) throws Exception {
        int port = DEFAULT_PORT;
        Path root = Path.of("shared");

        if (args.length >= 1) {
            port = Integer.parseInt(args[0]);
        }
        if (args.length >= 2) {
            root = Path.of(args[1]);
        }

        SecureShareServer app = new SecureShareServer(port, root);
        app.start();
        System.out.println("SecureShareServer running at http://localhost:" + port);
        System.out.println("Storage root: " + root.toAbsolutePath());
    }

    public void start() {
        server.start();
    }

    private HttpHandler withCors(HttpHandler next) {
        return ex -> {
            addCorsHeaders(ex);
            if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                sendJson(ex, 204, "{\"ok\":true}");
                return;
            }
            next.handle(ex);
        };
    }

    private void handleHealth(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            sendError(ex, 405, "Method not allowed.");
            return;
        }
        sendJson(ex, 200, "{\"ok\":true,\"service\":\"SecureShareServer\"}");
    }

    private void handleRegister(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            sendError(ex, 405, "Method not allowed.");
            return;
        }
        Map<String, String> body = readJsonBody(ex);
        String mailboxId = body.getOrDefault("mailboxId", "").trim();
        String passphrase = body.getOrDefault("passphrase", "");

        if (!validMailboxId(mailboxId)) {
            sendError(ex, 400, "Invalid mailboxId. Use 3-32 chars: letters, numbers, _ or -");
            return;
        }
        if (passphrase.isBlank()) {
            sendError(ex, 400, "Passphrase is required.");
            return;
        }

        Path mailboxDir = mailboxDir(mailboxId);
        Path meta = mailboxMetaPath(mailboxId);

        if (Files.exists(meta)) {
            sendJson(ex, 200, "{\"ok\":false,\"message\":\"Mailbox already exists.\"}");
            return;
        }

        try {
            Files.createDirectories(messagesDir(mailboxId));
            byte[] salt = randomBytes(16);
            byte[] hash = deriveHash(passphrase.toCharArray(), salt, PBKDF2_ITER, PBKDF2_BITS);

            Properties p = new Properties();
            p.setProperty("salt", b64(salt));
            p.setProperty("iter", String.valueOf(PBKDF2_ITER));
            p.setProperty("hash", b64(hash));
            p.setProperty("createdAt", Instant.now().toString());
            storeProps(meta, p);

            sendJson(ex, 200, "{\"ok\":true,\"mailboxId\":\"" + json(mailboxId) + "\"}");
        } catch (Exception e) {
            sendError(ex, 500, "Failed to create mailbox: " + e.getMessage());
        }
    }

    private void handleSend(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            sendError(ex, 405, "Method not allowed.");
            return;
        }
        Map<String, String> body = readJsonBody(ex);
        String mailboxId = body.getOrDefault("mailboxId", "").trim();
        String passphrase = body.getOrDefault("passphrase", "");
        String sender = body.getOrDefault("sender", "").trim();
        String b64Image = body.getOrDefault("stegoImageBase64", "");
        if (sender.isBlank()) sender = "anonymous";

        if (!validMailboxId(mailboxId)) {
            sendError(ex, 400, "Invalid mailboxId.");
            return;
        }
        if (!authenticate(mailboxId, passphrase)) {
            sendError(ex, 401, "Mailbox authentication failed.");
            return;
        }
        if (b64Image.isBlank()) {
            sendError(ex, 400, "stegoImageBase64 is required.");
            return;
        }

        try {
            byte[] pngBytes = decodeDataUrlOrBase64(b64Image);
            String messageId = UUID.randomUUID().toString();

            Path pngPath = messagePngPath(mailboxId, messageId);
            Path metaPath = messageMetaPath(mailboxId, messageId);
            Files.write(pngPath, pngBytes);

            Properties p = new Properties();
            p.setProperty("sender", sender);
            p.setProperty("timestamp", Instant.now().toString());
            p.setProperty("sizeBytes", String.valueOf(pngBytes.length));
            storeProps(metaPath, p);

            sendJson(ex, 200,
                    "{\"ok\":true,\"messageId\":\"" + json(messageId) + "\",\"sizeBytes\":" + pngBytes.length + "}");
        } catch (Exception e) {
            sendError(ex, 500, "Failed to save message: " + e.getMessage());
        }
    }

    private void handleList(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            sendError(ex, 405, "Method not allowed.");
            return;
        }
        Map<String, String> body = readJsonBody(ex);
        String mailboxId = body.getOrDefault("mailboxId", "").trim();
        String passphrase = body.getOrDefault("passphrase", "");

        if (!validMailboxId(mailboxId)) {
            sendError(ex, 400, "Invalid mailboxId.");
            return;
        }
        if (!authenticate(mailboxId, passphrase)) {
            sendError(ex, 401, "Mailbox authentication failed.");
            return;
        }

        try {
            Path msgDir = messagesDir(mailboxId);
            if (!Files.exists(msgDir)) Files.createDirectories(msgDir);

            List<Path> metaFiles;
            try (Stream<Path> stream = Files.list(msgDir)) {
                metaFiles = stream
                        .filter(p -> p.getFileName().toString().endsWith(".properties"))
                        .collect(Collectors.toList());
            }

            List<Map<String, String>> items = new ArrayList<>();
            for (Path meta : metaFiles) {
                String fileName = meta.getFileName().toString();
                String messageId = fileName.substring(0, fileName.length() - ".properties".length());
                if (!MESSAGE_ID_RE.matcher(messageId).matches()) continue;

                Properties p = loadProps(meta);
                Map<String, String> row = new HashMap<>();
                row.put("messageId", messageId);
                row.put("sender", p.getProperty("sender", "unknown"));
                row.put("timestamp", p.getProperty("timestamp", ""));
                row.put("sizeBytes", p.getProperty("sizeBytes", "0"));
                items.add(row);
            }

            items.sort(Comparator.comparing((Map<String, String> m) -> m.getOrDefault("timestamp", ""))
                    .reversed());

            StringBuilder sb = new StringBuilder();
            sb.append("{\"ok\":true,\"messages\":[");
            for (int i = 0; i < items.size(); i++) {
                Map<String, String> m = items.get(i);
                if (i > 0) sb.append(',');
                sb.append("{")
                        .append("\"messageId\":\"").append(json(m.get("messageId"))).append("\",")
                        .append("\"sender\":\"").append(json(m.get("sender"))).append("\",")
                        .append("\"timestamp\":\"").append(json(m.get("timestamp"))).append("\",")
                        .append("\"sizeBytes\":").append(parseLongSafe(m.get("sizeBytes")))
                        .append("}");
            }
            sb.append("]}");
            sendJson(ex, 200, sb.toString());
        } catch (Exception e) {
            sendError(ex, 500, "Failed to list messages: " + e.getMessage());
        }
    }

    private void handleDownload(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            sendError(ex, 405, "Method not allowed.");
            return;
        }
        Map<String, String> body = readJsonBody(ex);
        String mailboxId = body.getOrDefault("mailboxId", "").trim();
        String passphrase = body.getOrDefault("passphrase", "");
        String messageId = body.getOrDefault("messageId", "").trim();

        if (!validMailboxId(mailboxId) || !MESSAGE_ID_RE.matcher(messageId).matches()) {
            sendError(ex, 400, "Invalid mailboxId or messageId.");
            return;
        }
        if (!authenticate(mailboxId, passphrase)) {
            sendError(ex, 401, "Mailbox authentication failed.");
            return;
        }

        Path pngPath = messagePngPath(mailboxId, messageId);
        Path metaPath = messageMetaPath(mailboxId, messageId);
        if (!Files.exists(pngPath)) {
            sendError(ex, 404, "Message not found.");
            return;
        }

        try {
            byte[] bytes = Files.readAllBytes(pngPath);
            Properties p = Files.exists(metaPath) ? loadProps(metaPath) : new Properties();
            String sender = p.getProperty("sender", "unknown");
            String timestamp = p.getProperty("timestamp", "");

            String payload = "{\"ok\":true," +
                    "\"messageId\":\"" + json(messageId) + "\"," +
                    "\"sender\":\"" + json(sender) + "\"," +
                    "\"timestamp\":\"" + json(timestamp) + "\"," +
                    "\"imageBase64\":\"" + json(b64(bytes)) + "\"" +
                    "}";
            sendJson(ex, 200, payload);
        } catch (Exception e) {
            sendError(ex, 500, "Failed to download message: " + e.getMessage());
        }
    }

    private void handleDelete(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            sendError(ex, 405, "Method not allowed.");
            return;
        }
        Map<String, String> body = readJsonBody(ex);
        String mailboxId = body.getOrDefault("mailboxId", "").trim();
        String passphrase = body.getOrDefault("passphrase", "");
        String messageId = body.getOrDefault("messageId", "").trim();

        if (!validMailboxId(mailboxId) || !MESSAGE_ID_RE.matcher(messageId).matches()) {
            sendError(ex, 400, "Invalid mailboxId or messageId.");
            return;
        }
        if (!authenticate(mailboxId, passphrase)) {
            sendError(ex, 401, "Mailbox authentication failed.");
            return;
        }

        try {
            Files.deleteIfExists(messagePngPath(mailboxId, messageId));
            Files.deleteIfExists(messageMetaPath(mailboxId, messageId));
            sendJson(ex, 200, "{\"ok\":true}");
        } catch (Exception e) {
            sendError(ex, 500, "Failed to delete message: " + e.getMessage());
        }
    }

    private Map<String, String> readJsonBody(HttpExchange ex) throws IOException {
        String body = readBody(ex.getRequestBody());
        try {
            return SimpleJson.parseFlatStringMap(body);
        } catch (Exception e) {
            throw new IOException("Invalid JSON body.");
        }
    }

    private String readBody(InputStream in) throws IOException {
        return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }

    private void sendError(HttpExchange ex, int code, String msg) throws IOException {
        sendJson(ex, code, "{\"ok\":false,\"error\":\"" + json(msg) + "\"}");
    }

    private void sendJson(HttpExchange ex, int code, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static void addCorsHeaders(HttpExchange ex) {
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
    }

    private Path mailboxesRoot() {
        return root.resolve("inboxes");
    }

    private Path mailboxDir(String mailboxId) {
        return mailboxesRoot().resolve(mailboxId);
    }

    private Path mailboxMetaPath(String mailboxId) {
        return mailboxDir(mailboxId).resolve("mailbox.properties");
    }

    private Path messagesDir(String mailboxId) {
        return mailboxDir(mailboxId).resolve("messages");
    }

    private Path messagePngPath(String mailboxId, String messageId) {
        return messagesDir(mailboxId).resolve(messageId + ".png");
    }

    private Path messageMetaPath(String mailboxId, String messageId) {
        return messagesDir(mailboxId).resolve(messageId + ".properties");
    }

    private boolean validMailboxId(String mailboxId) {
        return MAILBOX_ID_RE.matcher(mailboxId).matches();
    }

    private boolean authenticate(String mailboxId, String passphrase) {
        if (passphrase == null || passphrase.isBlank()) return false;
        try {
            Path meta = mailboxMetaPath(mailboxId);
            if (!Files.exists(meta)) return false;
            Properties p = loadProps(meta);

            byte[] salt = b64Decode(p.getProperty("salt", ""));
            int iter = Integer.parseInt(p.getProperty("iter", String.valueOf(PBKDF2_ITER)));
            byte[] expected = b64Decode(p.getProperty("hash", ""));
            byte[] actual = deriveHash(passphrase.toCharArray(), salt, iter, expected.length * 8);
            return MessageDigest.isEqual(expected, actual);
        } catch (Exception e) {
            return false;
        }
    }

    private static Properties loadProps(Path p) throws IOException {
        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(p)) {
            props.load(in);
        }
        return props;
    }

    private static void storeProps(Path p, Properties props) throws IOException {
        Files.createDirectories(p.getParent());
        try (OutputStream out = Files.newOutputStream(p)) {
            props.store(out, null);
        }
    }

    private static byte[] deriveHash(char[] pass, byte[] salt, int iter, int bits) throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(pass, salt, iter, bits);
        return skf.generateSecret(spec).getEncoded();
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] b64Decode(String s) {
        return Base64.getDecoder().decode(s);
    }

    private static long parseLongSafe(String s) {
        try {
            return Long.parseLong(s);
        } catch (Exception e) {
            return 0L;
        }
    }

    private static byte[] decodeDataUrlOrBase64(String input) {
        String trimmed = input.trim();
        int comma = trimmed.indexOf(',');
        String b64 = (trimmed.startsWith("data:") && comma > 0) ? trimmed.substring(comma + 1) : trimmed;
        return Base64.getDecoder().decode(b64);
    }

    private static String json(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 12);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /**
     * Minimal JSON parser for flat object with string values.
     * Supports escaped quotes and backslashes.
     */
    static final class SimpleJson {
        private final String s;
        private int i;

        private SimpleJson(String s) {
            this.s = s;
        }

        public static Map<String, String> parseFlatStringMap(String json) {
            return new SimpleJson(json).parseObject();
        }

        private Map<String, String> parseObject() {
            Map<String, String> out = new HashMap<>();
            skipWs();
            expect('{');
            skipWs();
            if (peek('}')) {
                i++;
                return out;
            }

            while (true) {
                skipWs();
                String key = parseString();
                skipWs();
                expect(':');
                skipWs();
                String val = parseString();
                out.put(key, val);
                skipWs();
                if (peek(',')) {
                    i++;
                    continue;
                }
                if (peek('}')) {
                    i++;
                    break;
                }
                throw new IllegalArgumentException("Invalid JSON object.");
            }
            skipWs();
            if (i != s.length()) {
                throw new IllegalArgumentException("Trailing JSON content.");
            }
            return out;
        }

        private String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (i >= s.length()) throw new IllegalArgumentException("Bad escape.");
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"':
                            sb.append('"');
                            break;
                        case '\\':
                            sb.append('\\');
                            break;
                        case '/':
                            sb.append('/');
                            break;
                        case 'b':
                            sb.append('\b');
                            break;
                        case 'f':
                            sb.append('\f');
                            break;
                        case 'n':
                            sb.append('\n');
                            break;
                        case 'r':
                            sb.append('\r');
                            break;
                        case 't':
                            sb.append('\t');
                            break;
                        case 'u':
                            if (i + 4 > s.length()) throw new IllegalArgumentException("Bad unicode escape.");
                            String hex = s.substring(i, i + 4);
                            i += 4;
                            sb.append((char) Integer.parseInt(hex, 16));
                            break;
                        default:
                            throw new IllegalArgumentException("Bad escape character.");
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("Unterminated string.");
        }

        private void skipWs() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        }

        private void expect(char c) {
            if (i >= s.length() || s.charAt(i) != c) {
                throw new IllegalArgumentException("Expected '" + c + "'");
            }
            i++;
        }

        private boolean peek(char c) {
            return i < s.length() && s.charAt(i) == c;
        }
    }
}
