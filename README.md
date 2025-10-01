# E2EE Messaging App Server (Python)

This repository implements a full end-to-end encrypted messaging server using raw TCP sockets in Python.  
The protocol is custom-designed to support encrypted communication, authentication, digital signatures, and session management between clients — with strict adherence to security principles (confidentiality, integrity, authenticity, and non-repudiation).

---

## Features

- Custom protocol over TCP (binary format, little endian).
- RSA-2048 for key exchange and digital signatures.
- AES-256-CBC for symmetric encryption of payloads.
- SHA-256 for hashing and signing.
- OTP-based user registration and verification.
- Stateless server regarding message content (messages are never decrypted).
- SQLite-based persistent storage of users and pending messages.
- Multiclient support via socket mapping and threading.

---

## Registration and Key Exchange Flow

1. **Initial Registration**
   - Client sends encrypted registration request with phone number (RSA-encrypted with server’s public key).
   - If phone number is not in DB, server generates and sends a 6-digit OTP (code `200`).

2. **OTP Verification**
   - Client generates RSA key pair and sends:
     - Encrypted OTP
     - Public key (RSA)
     - Digital signature over payload
   - Server verifies signature + OTP, stores public key, generates AES session key encrypted with client’s public key (code `201`).

3. **Message Exchange**
   - Clients send encrypted AES messages + digital signature.
   - Server verifies signature and routes the message (code `102`).
   - If recipient is offline → store message in DB.
   - Recipient verifies signature using sender's public key and decrypts content with AES key.

---

## Packet Structure (Binary Format)

Each packet consists of:

| Field            | Size (bytes) | Description                         |
|------------------|--------------|-------------------------------------|
| sender_id        | 2            | ID of the sender                    |
| recipient_id     | 2            | ID of the recipient                 |
| timestamp        | 19           | Message timestamp                   |
| op_code          | 1            | Operation code                      |
| payload_size     | 2            | Size of encrypted payload           |
| payload          | variable     | AES-256-CBC encrypted content       |
| digital_signature| 256          | RSA signature on (header + payload)|

All fields are encoded using **Little Endian**.

---

## Operation Codes

| Code | Meaning                              |
|------|--------------------------------------|
| 100  | Registration request (phone)         |
| 101  | OTP + public key submission          |
| 102  | Message transmission                 |
| 105  | Request public key of another client |
| 106  | Reconnect request                    |
| 200  | OTP issued                           |
| 201  | AES session key issued               |
| 203  | Message delivery acknowledgment      |
| 204  | Public key response                  |
| 206  | AES session key for reconnect        |
| 222  | Disconnect acknowledgment            |
| 244  | Error response                       |
| 255  | No more messages                     |
| 150  | Registration rejected (phone exists) |

---

## Message Security

- All messages between clients are:
  - **Encrypted** with AES-256-CBC (with random IV).
  - **Signed** using RSA private key (SHA-256 hash).
- Server **never decrypts** message payloads.
- Packet integrity is verified via digital signature.
- All key exchange and OTP verification steps are signed and encrypted.

---

## SQLite Tables

1. `users`:  
   - `phone_number` (primary key)  
   - `rsa_public_key`  
   - `aes_key` (for session)  
   - `last_seen`

2. `pending_messages`:  
   - `message_id`  
   - `sender_id`, `recipient_id`  
   - `encrypted_payload`, `timestamp`

---

## How to Run

1. Install dependencies:
   ```bash
   pip install pycryptodome
