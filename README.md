
---

# SecureChat: Wasm-Powered End-to-End Encryption

**SecureChat** is a production-grade, browser-based messaging application that guarantees privacy through **End-to-End Encryption (E2EE)**.

It leverages **WebAssembly (C++ / OpenSSL)** to perform all cryptographic operations—Key Generation, Encryption, Decryption, and Signing—directly in the user's browser. The server acts strictly as a "blind courier," storing only encrypted blobs and routing packets without ever having access to user messages or private keys.

## Key Features

* **Hybrid Encryption Architecture:**
* **RSA-2048 (OAEP):** Used for Identity, Key Exchange, and Digital Signatures.
* **AES-128-CBC:** Used for high-speed symmetric message encryption.


* **Zero-Knowledge Authentication:**
* Private Keys are encrypted client-side using a key derived from the user's password (PBKDF2).
* The server stores the encrypted blob but cannot decrypt it.
* Users can log in from any device, unlocking their identity in memory.


* **High Performance:** powered by a custom C++ engine compiled to WebAssembly (Emscripten).
* **Real-Time Messaging:** Socket.io handles instant message delivery.
* **Memory Safety:** Strict RAII C++ patterns prevent memory leaks in the browser.

---

## Project Structure

```text
.
├── client/                  # Frontend (React + Vite)
│   ├── public/              # Hosts .wasm and .js bridge files
│   ├── src/
│   │   ├── api.js           # REST API & Password Derivation logic
│   │   └── App.jsx          # UI & Socket Logic
│   └── package.json
│
├── server/                  # Backend (Node.js + Express)
│   ├── index.js             # Auth endpoints & Socket.io routing
│   └── package.json
│
├── crypto/                  # Cryptographic Core (C++)
│   ├── openssl/             # Static OpenSSL libraries
│   ├── src/                 # Bridge code (bridge.cpp)
│   └── build.sh             # Compilation script

```

---

## Components Overview

### 1. The Crypto Engine (C++ / Wasm)

A standalone library providing the cryptographic primitives. It exposes a JavaScript class `PgpContext` that handles:

* `generateKeys()`: Creates RSA-2048 pairs.
* `encrypt(msg, key)` / `decrypt(hex, key)`: AES-128 operations.
* `rsaEncryptKey` / `rsaDecryptKey`: Secure session key exchange.
* `signMessage`: Authenticity verification using SHA-256.

### 2. The Client (React)

A modern SPA that manages the encryption lifecycle. It derives AES keys from user passwords to "unwrap" the private key from the server, ensuring the private key never exists in plaintext outside the Wasm memory.

### 3. The Backend (Node.js + PostgreSQL)

A lightweight signaling server.

* **Auth:** Stores `username`, `password_hash`, `public_key`, and `encrypted_priv_key`.
* **Routing:** Passes encrypted JSON packets between connected sockets.

---

## The Full Data Flow

### A. Registration (Zero-Knowledge)

1. **User** enters `username` and `password`.
2. **Wasm** generates a fresh RSA-2048 Keypair.
3. **Client** derives a 128-bit Key from `password` (PBKDF2).
4. **Client** encrypts the Private Key with this derived key.
5. **Client** sends `Public Key` + `Encrypted Private Key` to Server.

### B. Login & Identity Recovery

1. **User** enters `password`.
2. **Server** validates hash and returns the `Encrypted Private Key`.
3. **Client** re-derives the key from `password` and decrypts the Private Key into Wasm memory.

### C. The Chat Handshake (Alice -> Bob)

1. **Lookup:** Alice fetches Bob's Public Key from the server.
2. **Session:** Alice generates a random 128-bit **Session Key**.
3. **Encryption:** * Message is encrypted with Session Key (AES).
* Session Key is encrypted with Bob's Public Key (RSA).
* Ciphertext is signed with Alice's Private Key.


4. **Transport:** The JSON packet is sent via Socket.io.
5. **Decryption:** Bob uses his Private Key to decrypt the Session Key, then decrypts the message.

---

## Build & Installation Guide

### Prerequisites

* **Docker** (for PostgreSQL)
* **Node.js** (v18+)
* **Emscripten SDK** (for compiling C++)

### Step 1: Database Setup

Start a PostgreSQL container.

```bash
docker run --name pgp-db -e POSTGRES_PASSWORD=secret -d -p 5432:5432 postgres

```

Connect to the container and create the schema:

```bash
docker exec -it pgp-db psql -U postgres
# Paste the SQL below:
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_priv_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

```

### Step 2: Compile Wasm Engine

Build the C++ bridge and copy artifacts to the client.

```bash
cd crypto
./build.sh
# Output should confirm copy to ../client/public/

```

### Step 3: Start the Backend

```bash
cd ../server
npm install
node index.js
# Server listening on port 3000

```

### Step 4: Start the Frontend

```bash
cd ../client
npm install
npm run dev
# App running at http://localhost:5173

```

---

## Usage

1. Open two different browsers (or Incognito mode).
2. **User A:** Register as `alice`.
3. **User B:** Register as `bob`.
4. **User A:** Type `bob` in "Find User" and click Connect.
5. **Chat:** Type a message and send.
* *Observe:* The message appears in both windows.
* *Verify:* Check the console/logs to see that only **Encrypted Hex Strings** were transmitted over the network.



## 📄 License

MIT License. Educational Purpose Only.
