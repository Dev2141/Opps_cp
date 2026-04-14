# StegOS Explained (Natural Language Guide)

This document explains the whole system in plain language, with just enough code and technology detail to understand how it works and present it confidently.

---

## 1) What this project is, in one line

StegOS is a secure message/file sharing system where data is:

1. Wrapped into a structured payload,
2. Encrypted with a password (AES-256-GCM),
3. Hidden inside an image using LSB steganography,
4. Optionally shared through a mailbox-style API,
5. Extracted and decrypted by the receiver.

---

## 2) Big-picture architecture

The system has two sides:

- **Frontend (`index.html` + `styles.css` + `app.js`)**
  - User interface for Encode, Decode, Secure Share, and Analyzer.
  - Uses browser APIs (`Web Crypto`, `Canvas`, `FileReader`).

- **Java backend modules**
  - Core crypto/stego utilities (`EncryptionService`, `SteganographyEngine`, etc.).
  - Local sharing API server (`SecureShareServer`) to store/retrieve stego images by mailbox.

The frontend and backend follow the same concepts (same salt/key-derivation style, same `IV || ciphertext` format, same LSB header idea).

---

## 3) Why these technologies were used

### AES-256-GCM
- Chosen because it provides **confidentiality + integrity**.
- If the password is wrong or data is modified, decryption fails safely.

### PBKDF2-SHA256
- Converts human password into a strong encryption key.
- Slows down brute-force attempts using many iterations.

### LSB steganography
- Hides bits inside the least-significant bit of RGB channels.
- Visual quality stays almost unchanged for typical payload sizes.

### PNG output
- PNG is lossless, so hidden bits survive.
- JPEG is lossy and can destroy hidden data.

### Local HTTP API (`SecureShareServer`)
- Gives a practical “send/receive” flow without external cloud dependency.
- Easy to host later by moving from localhost to a public server.

---

## 4) End-to-end flow (user story)

### Sender flow
1. Selects a carrier image.
2. Chooses text or file as secret payload.
3. Enters encryption password.
4. Clicks **Encrypt and embed**.
5. Saves stego PNG or sends it via mailbox API.

### Receiver flow
1. Gets stego PNG (download from mailbox or manually).
2. Loads it in Decode.
3. Enters the same encryption password.
4. Clicks **Extract and decrypt**.
5. Receives original text/file.

---

## 5) Small code snippets of the core idea

### Encryption format (`IV || ciphertext`)
```js
const iv = crypto.getRandomValues(new Uint8Array(12));
const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, plain);
const out = new Uint8Array(12 + ct.byteLength);
out.set(iv, 0);
out.set(new Uint8Array(ct), 12);
```

### LSB write pattern
```js
for (let i = 0; i < data.length && bitIdx < totalBits; i += 4) {
  for (let c = 0; c < 3 && bitIdx < totalBits; c++) {
    data[i + c] = (data[i + c] & 0xfe) | nextBit;
  }
  data[i + 3] = 255; // keep alpha stable
}
```

### Mailbox API call (send)
```js
await apiPost("/api/message/send", {
  mailboxId,
  passphrase,
  sender,
  stegoImageBase64
});
```

---

## 6) Module-by-module explanation

## Frontend (`app.js`)

This file is the orchestration layer for the whole UI.

- It mounts templates into cards (`mountTemplates`), binds click/change handlers (`bindEvents`), and manages shared UI state (`state` object).
- It handles payload building/parsing (`buildEnvelope`, `parseEnvelope`) so text and files can be treated uniformly.
- It handles crypto (`deriveKey`, `aesEncrypt`, `aesDecrypt`) using browser `Web Crypto`.
- It handles stego embedding/extraction (`lsbEmbed`, `lsbExtract`) using hidden canvas image data.
- It handles sharing API operations (`handleRegisterMailbox`, `handleSendStego`, `handleRefreshInbox`, `handleDownloadSelected`, `handleDeleteSelected`).
- It handles analyzer scoring (`analyzeStego`) and pushes results to the Analyze panel (`handleAnalyze`).

In short: `app.js` is the runtime brain that connects UI, crypto, stego, sharing, and analysis.

## Encryption core (`EncryptionService.java`)

This is the Java equivalent of frontend encryption logic.

- `deriveKey(...)` uses PBKDF2-HMAC-SHA256.
- `encrypt(...)` creates random IV, runs AES-GCM, returns `IV || ciphertext`.
- `decrypt(...)` splits IV and ciphertext, then decrypts.

It ensures backend tools/CLI tests follow the same cryptographic format.

## Image utilities (`ImageHandler.java`)

Simple utility class:

- Load image into `BufferedImage`,
- Compute stego capacity,
- Save stego result as PNG.

## Payload format (`PayloadEnvelope.java`)

This class defines the binary envelope so both text and files are handled consistently.

Envelope contains:
- Magic: `STG1`
- Payload type: text/file
- File metadata (name + MIME)
- Actual payload bytes

This is what makes “hide file” and “hide text” work with one pipeline.

## LSB engine (`SteganographyEngine.java`)

Pure Java embedding/extraction module:

- `embed(...)`: writes `[length header + data]` into image RGB LSBs.
- `extract(...)`: reads bits back, reconstructs bytes, validates length.

It mirrors what canvas-based JavaScript version does.

## Analyzer (`StegoAnalyzer.java`)

Computes stego-likelihood metrics:
- LSB ratio per channel,
- Chi-based indicator,
- Entropy,
- Transition ratio,
- Header plausibility (important false-positive control),
- Final confidence + verdict.

This gives explainable “why” behind detection output instead of just yes/no.

## Sharing server (`SecureShareServer.java`)

A lightweight local HTTP API using Java `HttpServer`.

Main endpoints:
- `/api/mailbox/register`
- `/api/message/send`
- `/api/message/list`
- `/api/message/download`
- `/api/message/delete`

It stores mailbox and message metadata in filesystem folders and protects mailbox access via hashed passphrase verification.

## CLI extractor (`TestExtract.java`)

Developer/test helper:
- Reads stego image,
- Extracts hidden bytes,
- Decrypts with password,
- Prints message.

Useful for quick backend-side verification.

---

## 7) Input meanings (important for users)

There are two different passwords in this system:

- **Encryption password** (Encode/Decode):
  - Protects hidden secret data (AES key source).

- **Mailbox passphrase** (Secure Share):
  - Protects who can access mailbox inbox operations.

These are separate by design.

---

## 8) Full function map (plain-English purpose)

Below is every named function/method in the current system, with short natural-language purpose.

### `app.js`
- `mountTemplates`: Load all UI templates into cards.
- `setStatus`: Show status message + color.
- `hexToRgba`: Convert hex color to rgba.
- `formatBytes`: Human-readable byte formatting.
- `getPayloadMode`: Read selected payload mode.
- `updateModeUI`: Toggle text/file sections.
- `updateCapacityStats`: Refresh image/capacity chips.
- `estimateRequiredBytes`: Estimate bytes needed for current payload.
- `readFileAsDataURL`: File -> data URL.
- `readFileAsArrayBuffer`: File -> raw bytes.
- `loadImageFromUrl`: URL -> image object.
- `imageDataFromFile`: File -> canvas image data.
- `imageDataFromBase64`: Base64 PNG -> image data.
- `drawImageToData`: Draw image on canvas + read pixels.
- `canvasToBlob`: Canvas -> PNG blob.
- `downloadBlob`: Trigger browser file download.
- `buildEnvelope`: Build binary payload envelope.
- `looksLikeEnvelope`: Check envelope magic bytes.
- `parseEnvelope`: Parse envelope into payload object.
- `deriveKey`: PBKDF2 key derivation.
- `aesEncrypt`: Encrypt bytes with AES-GCM.
- `aesDecrypt`: Decrypt AES-GCM bytes.
- `lsbEmbed`: Hide bytes in image LSBs.
- `lsbExtract`: Recover hidden bytes from LSBs.
- `handleEmbed`: Main encode action pipeline.
- `isLosslessStegoDecodeType`: Validate decode file type.
- `setDecodeResult`: Write decode output in UI.
- `clearRecoveredFileLink`: Reset recovered file link.
- `handleExtract`: Main decode action pipeline.
- `base64ToBytes`: Base64 string -> byte array.
- `analyzeStego`: Compute analyzer metrics + confidence.
- `readStegoLengthHeader`: Read 32-bit LSB payload length header.
- `normalizedChi`: Normalize chi indicator.
- `binaryEntropy`: Compute binary entropy.
- `entropyTerm`: Helper for entropy formula.
- `clamp01`: Clamp value to [0,1].
- `getMailboxCreds`: Read mailbox credentials from UI.
- `apiPost`: Standard API POST wrapper.
- `handleRegisterMailbox`: Register mailbox.
- `handleSendStego`: Send current stego PNG to server.
- `escapeHtml`: Escape text for safe HTML rendering.
- `formatTime`: Format timestamp for table display.
- `renderInbox`: Render inbox rows and selection.
- `handleRefreshInbox`: Fetch and render inbox.
- `handleDownloadSelected`: Download selected message and pre-load decode panel.
- `handleDeleteSelected`: Delete selected inbox message.
- `handleAnalyze`: Run analyzer and render metrics.
- `loadCarrier`: Load carrier image for embedding.
- `bindEvents`: Attach all UI event handlers.

### `EncryptionService.java`
- `deriveKey`: Derive AES key from password.
- `encrypt`: Encrypt plaintext -> `IV || ciphertext`.
- `decrypt`: Decrypt `IV || ciphertext` -> plaintext.

### `ImageHandler.java`
- `load`: Read image file into memory.
- `capacityBytes`: Compute max hideable bytes.
- `savePNG`: Save image as PNG.

### `PayloadEnvelope.java`
- `PayloadEnvelope` constructor: Prevent object creation (utility class).
- `fromText`: Build text payload envelope.
- `fromFile`: Build file payload envelope.
- `looksLikeEnvelope`: Validate magic bytes.
- `parse`: Parse envelope bytes to structured result.
- `build`: Internal envelope byte builder.

### `PayloadEnvelope.DecodedPayload`
- `DecodedPayload` constructor: Internal parsed payload model.
- `text`: Create text payload result.
- `file`: Create file payload result.
- `asText`: Convert payload bytes to UTF-8 text.

### `SteganographyEngine.java`
- `embed`: Embed bytes in RGB LSBs.
- `extract`: Extract bytes from RGB LSBs.
- `getBit`: Read one bit from byte array.
- `setBit`: Set LSB of channel value.

### `StegoAnalyzer.java`
- `toString`: Report text representation.
- `analyze`: Compute analyzer report.
- `ratio`: Safe ratio helper.
- `normalizedChi`: Channel chi indicator.
- `lsbEntropy`: Entropy over LSB distribution.
- `entropyTerm`: Entropy math helper.
- `classify`: Confidence -> verdict.
- `clamp01`: Clamp helper.

### `SecureShareServer.java`
- `SecureShareServer` constructor: Build server + routes + storage root.
- `main`: CLI startup.
- `start`: Start HTTP server.
- `withCors`: CORS + OPTIONS wrapper.
- `handleHealth`: Health endpoint.
- `handleRegister`: Mailbox registration endpoint.
- `handleSend`: Save sent stego image.
- `handleList`: List mailbox messages.
- `handleDownload`: Download a message.
- `handleDelete`: Delete a message.
- `readJsonBody`: Parse request JSON.
- `readBody`: Read raw request body.
- `sendError`: Send JSON error response.
- `sendJson`: Send JSON response.
- `addCorsHeaders`: Add CORS headers.
- `mailboxesRoot`: Root inbox directory path.
- `mailboxDir`: Specific mailbox directory path.
- `mailboxMetaPath`: Mailbox metadata path.
- `messagesDir`: Mailbox messages directory.
- `messagePngPath`: Message PNG path.
- `messageMetaPath`: Message metadata path.
- `validMailboxId`: Validate mailbox ID format.
- `authenticate`: Verify mailbox passphrase hash.
- `loadProps`: Read `.properties`.
- `storeProps`: Write `.properties`.
- `deriveHash`: PBKDF2 hashing helper.
- `randomBytes`: Generate random bytes.
- `b64`: Base64 encode.
- `b64Decode`: Base64 decode.
- `parseLongSafe`: Safe long parsing.
- `decodeDataUrlOrBase64`: Accept base64 or data URL input.
- `json`: Escape text for JSON.

### `SecureShareServer.SimpleJson`
- `SimpleJson` constructor: Parser state setup.
- `parseFlatStringMap`: Parse flat JSON object.
- `parseObject`: Parse object structure.
- `parseString`: Parse string tokens.
- `skipWs`: Skip whitespace.
- `expect`: Require specific char.
- `peek`: Check next char.

### `TestExtract.java`
- `main`: CLI extraction + decryption test run.
- `deriveKey`: PBKDF2 key derivation for test flow.

---

## 9) Practical limits and notes

- Always decode from **PNG/BMP stego output**, not JPEG.
- Analyzer is heuristic, not a legal-grade certainty engine.
- Mailbox API is local-first; for production, host server with HTTPS and stricter CORS.

---

If you want, I can also create a second file: `VIVA_QNA.md` with likely interview questions + short confident answers.
