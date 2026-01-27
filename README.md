
# SecureChat PGP (WebAssembly Core)

**SecureChat** is a proof-of-concept cryptographic engine that brings professional-grade **OpenSSL 3.1** to the browser using **WebAssembly**. 

It implements a **Hybrid PGP Encryption Scheme** (RSA + AES) to enable secure, end-to-end encrypted messaging directly in the client, with no sensitive keys ever touching a server.

## Features

* **C++ Core:** Powered by a custom C++ bridge linked against a static OpenSSL build.
* **WebAssembly:** Compiled via Emscripten for near-native performance in the browser.
* **Hybrid Encryption:**
    * **RSA-2048:** For Identity, Key Exchange, and Digital Signatures (OAEP/SHA-256).
    * **AES-128-CBC:** For high-speed symmetric message encryption.
* **Memory Safe:** RAII-compliant C++ memory management to prevent leaks in long-running sessions.
* **React Frontend:** A modern dashboard to generate identities, perform handshakes, and exchange messages.

## Architecture

The application follows the standard PGP (Pretty Good Privacy) workflow:

1.  **Identity:** Users generate an RSA-2048 Keypair locally.
2.  **Handshake:** Users exchange **Public Keys**.
3.  **Session:** * Sender generates a random **128-bit AES Session Key**.
    * Message is encrypted with the **Session Key** (AES).
    * Session Key is encrypted with Receiver's **Public Key** (RSA).
    * Ciphertext is **Signed** with Sender's **Private Key** (RSA).
4.  **Transport:** The packet `{ "aesCipher", "encryptedKey", "signature" }` is sent over the wire.

## Project Structure

```text
.
├── client/          # React Frontend (Vite)
│   ├── public/      # Hosts the .wasm and .js glue code
│   └── src/         # UI Logic (App.jsx)
├── crypto/          # C++ Core
│   ├── openssl/     # OpenSSL source and static libs (.a)
│   ├── src/         # Bridge code (bridge.cpp)
│   ├── CMakeLists.txt
│   └── build.sh     # Compilation script
└── README.md

```

## Prerequisites

* **Linux / WSL2** (Required for OpenSSL compilation)
* **Emscripten SDK** (emsdk) active in your environment
* **CMake** (3.10+)
* **Node.js** (v18+)

## Build Instructions

### 1. Compile the C++ Core

The build script compiles the C++ bridge, links OpenSSL, and copies the artifacts to the React public folder.

```bash
cd crypto
./build.sh

```

*Expected Output:* `Build Successful! Files secure_chat.js and .wasm are in crypto/build/`

### 2. Run the Frontend

Navigate to the client folder, install dependencies, and start the Vite server.

```bash
cd ../client
npm install
npm run dev

```

Open your browser to `http://localhost:5173`.

## Usage Guide

### Generating an Identity

1. Go to the **"My Identity"** section in the UI.
2. Click **"Generate New Keypair"**.
3. Wait for the C++ engine to find large primes (approx 0.5s).
4. Your Public and Private keys will appear.

### Simulating a Chat

1. **Partner Setup:** Copy your **Public Key** and paste it into the **"Partner Setup"** box (simulating a self-chat for testing).
2. **Send Message:** Type a message in the "Secure Message" box and click **"Encrypt & Sign Packet"**.
3. **Verify:** Click **"Verify / Decrypt"** to let the engine reverse the process:
* Decrypt the Session Key using your Private Key.
* Decrypt the Message using the Session Key.



## Security Note

This project uses **OpenSSL 3.0+** primitives, which are industry standard. However, this is a portfolio/educational project.

* **Randomness:** Uses `window.crypto.getRandomValues` for AES keys.
* **Storage:** Private keys are stored in React state (RAM) only.

*Do not use for critical security applications without a full security audit.*

## License

MIT
