# StegOS Secure Suite

StegOS Secure Suite is a privacy-first steganography system that encrypts data, hides it inside images, shares stego images through authenticated mailboxes, and analyzes images for hidden-content indicators. The guiding idea is simple: encrypt first, hide second, share safely, and verify with analysis.

## Table of contents

- [Project summary](#project-summary)
- [System overview](#system-overview)
- [Feature summary table](#feature-summary-table)
- [Feature deep dive](#feature-deep-dive)
- [Supporting capabilities](#supporting-capabilities)
- [Algorithms reference](#algorithms-reference)
- [Java OOP concepts mapping](#java-oop-concepts-mapping)
- [Repository map](#repository-map)
- [Run locally](#run-locally)
- [Practical notes](#practical-notes)

## Project summary

StegOS is built to demonstrate secure communication through steganography and modern cryptography, while remaining practical for demos and academic use.

- It hides both text and full files inside images.
- It encrypts payloads with AES-256-GCM using PBKDF2-derived keys.
- It provides mailbox-based sharing with server-side authentication.
- It includes a statistical analyzer to detect likely stego content.

## System overview

### Components

| Layer | Responsibilities | Key files |
| --- | --- | --- |
| Browser UI | UX, encryption, stego embed/extract, analysis, and API calls | [index.html](index.html), [styles.css](styles.css), [app.js](app.js) |
| Java core | Crypto utilities, payload handling, stego engine, analyzer | [EncryptionService.java](EncryptionService.java), [PayloadEnvelope.java](PayloadEnvelope.java), [SteganographyEngine.java](SteganographyEngine.java), [StegoAnalyzer.java](StegoAnalyzer.java), [ImageHandler.java](ImageHandler.java) |
| Share API | Mailbox endpoints and storage logic | [SecureShareServer.java](SecureShareServer.java), [shared](shared) |
| Launcher | Local server startup and proxy | [server.py](server.py) |

### Data flow (high level)

Secret -> Payload envelope -> AES-256-GCM -> LSB embed -> Stego PNG -> Share API (optional) -> LSB extract -> AES-256-GCM decrypt -> Envelope parse -> Text or file

## Feature summary table

| Feature | What it does | Core algorithms | OOP concepts used |
| --- | --- | --- | --- |
| Hide (Encrypt + Embed) | Protects and hides payload inside an image | PBKDF2, AES-256-GCM, LSB embed | Encapsulation, SRP, composition |
| Extract (Recover + Decrypt) | Recovers hidden data and restores content | LSB extract, AES-256-GCM | Abstraction, immutability, SRP |
| Secure Share (Mailboxes) | Sends and receives stego images via authenticated inboxes | PBKDF2 hash, Base64, UUID | Encapsulation, interface usage, composition |
| Stego Analyzer | Estimates if an image likely contains hidden data | Chi indicator, entropy, transitions, header check | SRP, data model class |

## Feature deep dive

### Feature 1: Hide (Encrypt and embed)

- **What it does:** Takes a secret text or file, wraps it in a structured envelope, encrypts it, and embeds it into the least-significant bits of a carrier image. The output is a lossless PNG.
- **Algorithms used:** PBKDF2-HMAC-SHA256 for key derivation, AES-256-GCM for encryption and integrity, LSB embedding for steganography, PNG lossless output to preserve hidden bits.
- **OOP concepts used:** Encapsulation via `EncryptionService` and `SteganographyEngine`, SRP through separate classes for crypto, stego, and payload formatting, composition because these modules are orchestrated together by the UI logic.
- **Key files:** [app.js](app.js), [PayloadEnvelope.java](PayloadEnvelope.java), [EncryptionService.java](EncryptionService.java), [SteganographyEngine.java](SteganographyEngine.java), [ImageHandler.java](ImageHandler.java)
- **Flow:** 1) collect secret -> 2) build envelope -> 3) derive key -> 4) encrypt -> 5) embed -> 6) export PNG.

### Feature 2: Extract (Recover and decrypt)

- **What it does:** Reads hidden bytes from a stego image, decrypts them with the same password, then restores the original text or file.
- **Algorithms used:** LSB extraction to recover the ciphertext, AES-256-GCM decryption with integrity verification, envelope parsing to recover metadata and payload.
- **OOP concepts used:** Abstraction because `PayloadEnvelope.parse` hides binary details, immutability in `DecodedPayload` fields, SRP in classes that each handle one responsibility.
- **Key files:** [app.js](app.js), [PayloadEnvelope.java](PayloadEnvelope.java), [EncryptionService.java](EncryptionService.java), [SteganographyEngine.java](SteganographyEngine.java), [TestExtract.java](TestExtract.java)
- **Flow:** 1) load stego image -> 2) extract bytes -> 3) decrypt -> 4) parse envelope -> 5) show text or download file.

### Feature 3: Secure Share (Mailbox messaging)

- **What it does:** Provides a local mailbox system where users register an inbox, send stego images, list messages, download a message, and delete it after retrieval.
- **Algorithms used:** PBKDF2-HMAC-SHA256 for passphrase hashing, Base64 for image transport, UUID for message identifiers.
- **OOP concepts used:** Encapsulation in `SecureShareServer`, interface-based design via `HttpHandler`, composition through reusable request wrappers like `withCors`.
- **Key files:** [SecureShareServer.java](SecureShareServer.java), [server.py](server.py), [shared](shared), [app.js](app.js)
- **Flow:** 1) register mailbox -> 2) authenticate -> 3) send or list -> 4) download -> 5) delete.

### Feature 4: Stego Analyzer (Detection report)

- **What it does:** Runs statistical checks on an image and produces a confidence score with a verdict: likely hidden data, suspicious, or likely clean.
- **Algorithms used:** LSB ratio balance per channel, chi-style anomaly indicator, binary entropy, bit transition ratio, header plausibility check.
- **OOP concepts used:** SRP in `StegoAnalyzer` focusing only on analysis, data model in `Report` for clean output structure.
- **Key files:** [StegoAnalyzer.java](StegoAnalyzer.java), [app.js](app.js)
- **Flow:** 1) scan image pixels -> 2) compute metrics -> 3) score confidence -> 4) label verdict.

## Supporting capabilities

### Unified payload envelope

- **What it does:** Stores both text and file payloads in one binary format with metadata and length fields, so the same pipeline works for both.
- **Algorithm or format:** Fixed header `STG1`, type flag, file name and MIME lengths, payload length, then data.
- **OOP concepts used:** Utility class pattern and factory methods in `PayloadEnvelope` for clarity and safety.
- **Key files:** [PayloadEnvelope.java](PayloadEnvelope.java), [app.js](app.js)

### Capacity awareness and lossless output

- **What it does:** Shows how much space an image can carry and ensures the output is lossless to keep embedded bits intact.
- **Algorithms used:** Capacity = width * height * 3 / 8 bytes, PNG export for lossless storage.
- **OOP concepts used:** SRP in `ImageHandler` for image I/O utilities.
- **Key files:** [ImageHandler.java](ImageHandler.java), [app.js](app.js)

### Local launcher and proxy

- **What it does:** Compiles Java, starts the share API, serves the frontend, and proxies share endpoints for the browser.
- **Algorithms used:** HTTP proxying and health checks, simple process management.
- **OOP concepts used:** Procedural orchestration in a single script for simplicity.
- **Key files:** [server.py](server.py)

## Algorithms reference

| Area | Algorithm or method | Purpose |
| --- | --- | --- |
| Key derivation | PBKDF2-HMAC-SHA256 | Turn password into a strong AES key |
| Encryption | AES-256-GCM | Confidentiality and integrity |
| Steganography | LSB embed and extract | Hide bits in image channels |
| Analysis | Chi indicator, entropy, transitions | Detect suspicious stego patterns |
| Mailbox auth | PBKDF2-HMAC-SHA256 + constant time compare | Protect inbox access |
| Data transport | Base64 | Move images through JSON APIs |

## Java OOP concepts mapping

| OOP concept | Where it appears | Why it matters |
| --- | --- | --- |
| Encapsulation | `EncryptionService`, `SteganographyEngine`, `SecureShareServer` | Keeps data and logic together and easy to reuse |
| Abstraction | `PayloadEnvelope.parse`, `StegoAnalyzer.analyze` | Hides low-level details behind clean methods |
| Single Responsibility | Separate classes for crypto, stego, analysis, image I/O | Improves testability and clarity |
| Immutability | `PayloadEnvelope.DecodedPayload` fields are `final` | Prevents accidental changes after parsing |
| Factory methods | `DecodedPayload.text`, `DecodedPayload.file` | Creates valid objects with clear intent |
| Composition | Modules orchestrated in UI logic | Enables flexible feature assembly |
| Interface usage | `HttpHandler` in the share server | Enables consistent request handling |

## Repository map

| File or folder | Responsibility |
| --- | --- |
| [app.js](app.js) | Browser logic for crypto, stego, analyzer, and mailbox calls |
| [index.html](index.html) | UI structure for Dashboard, Hide, Extract, Share, Analyze |
| [styles.css](styles.css) | Visual system and component styling |
| [server.py](server.py) | Local launcher and API proxy |
| [SecureShareServer.java](SecureShareServer.java) | Mailbox API endpoints and storage |
| [EncryptionService.java](EncryptionService.java) | PBKDF2 and AES-GCM crypto helpers |
| [PayloadEnvelope.java](PayloadEnvelope.java) | Unified payload format for text and files |
| [SteganographyEngine.java](SteganographyEngine.java) | LSB stego embedding and extraction |
| [StegoAnalyzer.java](StegoAnalyzer.java) | Statistical stego detection and confidence report |
| [ImageHandler.java](ImageHandler.java) | Image loading, capacity, and PNG export |
| [TestExtract.java](TestExtract.java) | CLI verification for extraction and decryption |
| [shared](shared) | Local mailbox storage root |
| [EXPLANATION_README.md](EXPLANATION_README.md) | Long-form explanation document |
| [plan.md](plan.md) | Upgrade plan and implementation scope |

## Run locally

### Option A: Use the launcher

1. Make sure JDK and Python are installed.
2. Run the launcher script (see [server.py](server.py)):

```bash
python <launcher-script>
```

Replace `<launcher-script>` with the launcher file name from the link above.

This will:
- Compile Java if needed.
- Start the Java API on port 8088.
- Serve the frontend on port 8080.
- Proxy `/share-api/*` to the backend.

### Option B: Manual steps

```bash
javac *.java
java SecureShareServer 8088
```

Then open [index.html](index.html) in a browser (or serve it with any static server).

## Practical notes

- Always use PNG or BMP for extraction. JPEG is lossy and may destroy hidden data.
- The analyzer provides a probability-style verdict, not legal proof.
- For production use, add HTTPS, stricter CORS, and server hardening.
