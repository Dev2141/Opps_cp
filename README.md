# StegOS Secure Suite

StegOS Secure Suite is a privacy-first steganography project that helps users hide sensitive information inside normal-looking images, recover it securely, share stego images through authenticated mailboxes, and analyze images for possible hidden content.

This project combines cryptography, image processing, and a practical sharing workflow. It is designed for learning, demonstrations, and secure local experimentation.

## 1. Project Objectives

The core objectives of this project are:

1. Protect secret data before embedding.
   The project encrypts data first, then hides it inside an image. This means hidden data is not only concealed, but also cryptographically protected.

2. Support both messages and files.
   The project is not limited to plain text. It supports hiding full files with metadata so they can be reconstructed correctly during extraction.

3. Keep operations simple for users.
   The interface guides users through hide, extract, share, and analyze workflows in a practical way.

4. Provide an end-to-end secure sharing model.
   Users can register inbox-style mailboxes, send stego images, retrieve them, and delete them, all behind mailbox authentication.

5. Include detection and analysis capability.
   The analyzer estimates whether an image likely contains hidden content using statistical indicators.

6. Work locally without cloud dependency by default.
   Core encode/decode/analyze functions run in the browser. Secure share can run on a local Java server, with optional public access via tunnel.

## 2. What Problem This Project Solves

Traditional communication channels can expose the existence of sensitive data. Even when a message is encrypted, observers can still see that a secret message exists.

StegOS addresses this by combining:

1. Confidentiality through encryption.
2. Concealment through steganography.
3. Practical distribution through mailbox-based sharing.
4. Verification through stego analysis.

So the project does not only hide content; it provides a full secure communication workflow.

## 3. How the Project Works End to End

The system has four functional modes.

### Hide Mode

1. The user selects a carrier image.
2. The user chooses secret content type: text or file.
3. The system wraps data into a structured payload envelope.
4. The payload is encrypted using password-derived AES-256-GCM.
5. The encrypted bytes are embedded into image pixel least-significant bits.
6. The output is exported as a lossless PNG so hidden bits survive.

### Extract Mode

1. The user loads a stego image.
2. The system extracts hidden bits and reconstructs encrypted payload bytes.
3. The user-provided password is used to decrypt the payload.
4. The envelope is parsed to restore either text or original file.
5. The recovered output is shown for copy or downloaded as a file.

### Secure Share Mode

1. A mailbox is registered with mailbox ID and passphrase.
2. A generated stego image is sent to that mailbox.
3. Inbox list retrieves available messages with sender and timestamp.
4. A selected message can be downloaded and loaded into extract flow.
5. Messages can be deleted from mailbox storage after use.

### Analyze Mode

1. A target image is loaded.
2. LSB and channel statistics are measured.
3. Multiple indicators are combined into confidence score.
4. The result is classified into likely clean, suspicious, or likely hidden data.

## 4. Technology Stack Used

This project uses a mixed frontend-backend architecture.

### Frontend Technologies

1. HTML for structure and feature views.
2. CSS for dashboard and interactive UI styling.
3. JavaScript for application logic and orchestration.
4. Browser Web Crypto API for encryption and key derivation.
5. Canvas API for pixel-level steganography operations.
6. File APIs for reading and generating downloadable outputs.
7. Bootstrap and icon assets for UI components and visual consistency.
8. GSAP animations for guided transitions and interactions.

### Backend Technologies

1. Java for secure sharing server and core algorithm modules.
2. Java HttpServer for lightweight API hosting.
3. Java cryptography primitives for password hashing and validation.
4. Filesystem-based mailbox storage using properties metadata plus image files.

### Launcher and Utility Technologies

1. Python launcher script to simplify startup of frontend and backend.
2. Optional ngrok tunnel integration for exposing local share API publicly.

## 5. Core Security Model

The project uses layered security instead of relying on only one technique.

### Layer 1: Encryption

The payload is encrypted before embedding, so raw secret data is never written directly into image bits.

### Layer 2: Password-Based Key Derivation

A user password is transformed into a strong cryptographic key using PBKDF2 and many iterations. This reduces risk from weak direct password usage.

### Layer 3: Authenticated Encryption

AES-GCM not only encrypts data but also verifies integrity during decryption. If bytes are modified or password is wrong, extraction fails safely.

### Layer 4: Concealment in Carrier Image

Ciphertext is hidden in low-impact image bits so the image appears visually normal under casual viewing.

### Layer 5: Mailbox Access Protection

Mailbox credentials are validated using hashed passphrase material, limiting unauthorized access to inbox operations.

## 6. Detailed Feature Explanation

### 6.1 Unified Payload Envelope

The project stores secret data in a structured envelope format that includes payload type and metadata.

Why this matters:

1. One common pipeline supports both text and files.
2. File name and MIME metadata help accurate reconstruction.
3. Future extension is easier because payload format is explicit.

### 6.2 Text and File Hiding

Users can hide a short message or a complete file. This makes the system practical for many scenarios such as notes, credentials bundles, documents, and binary attachments.

Why this matters:

1. It is not just a message demo.
2. File-level support increases real-world usefulness.

### 6.3 Capacity Awareness Before Embedding

The UI estimates required space and available image capacity before encoding.

Why this matters:

1. Prevents failed embeddings.
2. Helps users pick suitable carrier image dimensions.
3. Improves UX with predictable behavior.

### 6.4 Lossless Output Strategy

The generated stego image is saved as PNG. This is intentional because lossy formats such as JPEG can damage hidden bits.

Why this matters:

1. Preserves recoverability.
2. Reduces accidental data loss after embedding.

### 6.5 Extraction with Content Auto-Handling

During extraction, the app determines whether decrypted content is text or file and then renders the correct recovery path automatically.

Why this matters:

1. Less manual handling for users.
2. Clean output experience for both payload types.

### 6.6 Mailbox Registration and Authentication

A mailbox ID and passphrase model is used to gate message operations.

Why this matters:

1. Prevents open anonymous inbox access.
2. Allows simple identity separation among users.
3. Keeps implementation lightweight for local or lab usage.

### 6.7 Send, List, Download, and Delete Messaging Workflow

Secure Share includes full inbox lifecycle operations, not only send.

Why this matters:

1. Creates complete communication loop.
2. Makes receiver workflow practical.
3. Supports cleanup after retrieval.

### 6.8 Auto-Handoff from Share to Extract

Downloaded mailbox messages can be loaded directly into extraction flow.

Why this matters:

1. Reduces friction for receiver.
2. Connects modules as one continuous workflow.

### 6.9 Statistical Stego Analyzer

Analyzer computes several indicators and combines them into confidence score and verdict.

Main indicators explained:

1. LSB ratio balance by channel.
   Measures how 0 and 1 bits are distributed in least-significant positions.

2. Chi-based channel indicator.
   Looks for parity patterns that often shift after embedding.

3. Entropy term.
   Captures randomness behavior in extracted bit distribution.

4. Bit transition ratio.
   Observes local bit change frequency across read order.

5. Header plausibility check.
   Evaluates whether early embedded length pattern is structurally believable.

Why this matters:

1. Gives explainable analysis instead of blind yes/no output.
2. Useful for education and controlled forensic demonstrations.

### 6.10 Local-First Privacy Model

Hide, extract, and analyze operate directly in browser runtime on local machine.

Why this matters:

1. Reduces dependence on external services.
2. Improves privacy in demos and offline environments.

## 7. Project Architecture by File Responsibility

### Frontend Core

1. index.html
   Hosts all views and interactive sections for dashboard, hide, extract, share, and analyze.

2. styles.css
   Defines visual design, layout behavior, feature cards, panels, and responsive behavior.

3. app.js
   Main browser logic for encryption, steganography, API calls, UI state, and analyzer logic.

### Java Core and API

1. EncryptionService.java
   Handles key derivation and authenticated encryption/decryption.

2. PayloadEnvelope.java
   Defines unified payload format for text and file transfer.

3. SteganographyEngine.java
   Handles LSB embedding and extraction mechanics in Java form.

4. StegoAnalyzer.java
   Produces analysis report and confidence classification.

5. ImageHandler.java
   Handles image loading, capacity calculation, and PNG saving utilities.

6. SecureShareServer.java
   Provides mailbox API endpoints and filesystem-backed message storage.

7. TestExtract.java
   Utility test path for extraction and decryption verification.

### Launcher and Runtime Support

1. server.py
   Unified launcher that can compile Java, start share API, start frontend server, and optionally configure a public tunnel.

## 8. Operational Workflow in Practical Use

A practical usage sequence is:

1. Start the suite locally through the launcher.
2. Hide text or file in a selected carrier image.
3. Download stego PNG output.
4. Share through mailbox workflow.
5. Receiver downloads message from inbox.
6. Receiver extracts and decrypts with agreed password.
7. Optional analyzer checks suspicion level on target images.

## 9. Design Strengths

This project is strong in the following areas:

1. End-to-end thought process from generation to distribution to recovery.
2. Clear separation between concealment and cryptographic protection.
3. Practical local API model for collaboration demonstrations.
4. Better interpretability through analyzer metrics.
5. Unified payload design that scales from text to binary file handling.

## 10. Current Constraints and Important Notes

1. Stego output should remain in lossless formats for reliable recovery.
2. Analyzer output is heuristic confidence, not absolute legal proof.
3. Mailbox protection is suitable for controlled environments and learning use.
4. Production deployment should add hardened controls such as strict HTTPS and stronger operational governance.

## 11. Ideal Use Cases

1. Academic demonstrations of cryptography plus steganography.
2. Security lab projects and viva presentations.
3. Prototype private communication workflows.
4. Stego detection experiments and metric interpretation training.

## 12. Summary

StegOS Secure Suite is a complete secure steganography system, not only an embedding script. It provides:

1. Confidential hidden payload creation.
2. Reliable extraction and content recovery.
3. Authenticated mailbox-based stego sharing.
4. Statistical analyzer for hidden-data suspicion scoring.

As a project, it demonstrates strong understanding of security layering, practical software architecture, and real-world communication flow design.
