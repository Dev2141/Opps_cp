# StegOS Upgrade Plan

## Goal
Convert the current steganography demo into a practical secure communication tool with:
1. Secure stego image sharing between users
2. File hiding support (not text-only)
3. Stego image analyzer report

## Implemented Scope
- Unified payload envelope for text and files (`STG1` header)
- AES-256-GCM encryption and LSB embedding/extraction pipeline
- Browser UI for encode/decode/share/analyze in a professional light theme
- Local Java sharing API with mailbox authentication
- Statistical analyzer logic for confidence-based detection

## Main Data Flow
1. Message/File -> Payload Envelope -> AES Encrypt -> LSB Embed -> Stego PNG
2. Stego PNG -> API Send (optional) -> Receiver Download
3. Stego PNG -> LSB Extract -> AES Decrypt -> Envelope Parse -> Text/File recovery
4. Analyzer reads image LSB statistics and generates confidence + verdict

## API Endpoints
- `POST /api/mailbox/register`
- `POST /api/message/send`
- `POST /api/message/list`
- `POST /api/message/download`
- `POST /api/message/delete`

## Notes
- Mailbox identity model: `mailboxId + passphrase`
- Password hashes are PBKDF2-based and only hash/salt are stored
- Existing text payload compatibility is kept via legacy fallback decode
