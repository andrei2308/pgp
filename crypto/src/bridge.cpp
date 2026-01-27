#include <emscripten/bind.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

using namespace emscripten;

/// @brief Bridge class to expose OpenSSL crypto primitives to JavaScript via WebAssembly.
class PgpContext {
private:
    /// @brief Converts a Hex string (e.g., "48656C6C6F") to raw binary bytes.
    /// @param hex The hex string to parse.
    /// @return A std::string containing raw binary data.
    std::string hexToBytes(const std::string& hex) {
        std::string bytes;
        for (unsigned int i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            char byte = (char)strtol(byteString.c_str(), NULL, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    /// @brief Converts raw binary data to a Hex string.
    /// @param data Pointer to the binary buffer.
    /// @param len Length of the buffer.
    /// @return A Hex representation string.
    std::string toHex(const unsigned char* data, int len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < len; ++i) {
            ss << std::setw(2) << (int)data[i];
        }
        return ss.str();
    }

    /// @brief Loads an EVP_PKEY from a PEM string.
    /// @param pem The private key string (PEM format).
    EVP_PKEY* loadPrivateKey(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.c_str(), -1);
        if (!bio) return NULL;
        EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        return key;
    }

    /// @brief Loads an EVP_PKEY Public Key from a PEM string.
    /// @param pem The public key string (PEM format).
    EVP_PKEY* loadPublicKey(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.c_str(), -1);
        if (!bio) return NULL;
        EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        return key;
    }

public:
    PgpContext() {}

    /// @brief Simple health check to verify OpenSSL linking.
    /// @return Status string.
    std::string checkStatus() {
        return "OpenSSL 3.1 Loaded & Ready";
    }

    // --- SYMMETRIC ENCRYPTION (AES) ---

    /// @brief Encrypts a string using AES-128-CBC.
    /// @param input The plaintext string.
    /// @return Ciphertext encoded as a Hex string.
    std::string encrypt(std::string input) {
        const EVP_CIPHER* cipher = EVP_aes_128_cbc();
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        
        // Todo: Accept Key/IV as parameters in production
        unsigned char key[16] = {0};
        unsigned char iv[16] = {0};

        EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

        int inputLen = input.length();
        int paddingLen = 16 - (inputLen % 16);
        unsigned char* out = new unsigned char[inputLen + paddingLen];

        int outlen;
        int finalLen;
        EVP_EncryptUpdate(ctx, out, &outlen, (unsigned char*) input.c_str(), input.length());
        EVP_EncryptFinal_ex(ctx, out + outlen, &finalLen);

        EVP_CIPHER_CTX_free(ctx);
        std::string result = toHex(out, outlen + finalLen);
        delete[] out;
        return result;
    }

    /// @brief Decrypts a Hex-encoded string using AES-128-CBC.
    /// @param inputHex The ciphertext in Hex format.
    /// @return Plaintext string or error message.
    std::string decrypt(std::string inputHex) {
        std::string ciphertext = hexToBytes(inputHex);

        const EVP_CIPHER* cipher = EVP_aes_128_cbc();
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        unsigned char key[16] = {0};
        unsigned char iv[16] = {0};

        if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "Error: Init Failed";
        }

        unsigned char* out = new unsigned char[ciphertext.length()];
        int outlen;
        int finalLen;

        if (EVP_DecryptUpdate(ctx, out, &outlen, (unsigned char*)ciphertext.c_str(), ciphertext.length()) != 1) {
             delete[] out; EVP_CIPHER_CTX_free(ctx); return "Error: Update";
        }

        if (EVP_DecryptFinal_ex(ctx, out + outlen, &finalLen) != 1) {
             delete[] out; EVP_CIPHER_CTX_free(ctx); return "Error: Bad Padding/Key";
        }

        EVP_CIPHER_CTX_free(ctx);
        std::string result((char*)out, outlen + finalLen);
        delete[] out;
        return result;
    }

    // --- ASYMMETRIC ENCRYPTION (RSA Key Exchange) ---

    /// @brief Encrypts a Session Key (raw bytes) using RSA-OAEP.
    /// @param sessionKeyBytes Raw binary string of the AES key.
    /// @param pubKeyPem The receiver's Public Key (PEM).
    /// @return Encrypted Session Key as Hex string.
    std::string rsaEncryptKey(std::string sessionKeyBytes, std::string pubKeyPem){
        EVP_PKEY* pubKey = loadPublicKey(pubKeyPem);
        if (!pubKey) return "Error: Load PubKey";

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubKey, NULL);
        if (!ctx) { EVP_PKEY_free(pubKey); return "Error: Context"; }

        if (EVP_PKEY_encrypt_init(ctx) <= 0) return "Error: Init";
        
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return "Error: Padding";

        size_t outlen;
        EVP_PKEY_encrypt(ctx, NULL, &outlen, (unsigned char*)sessionKeyBytes.c_str(), sessionKeyBytes.length());

        unsigned char* out = new unsigned char[outlen];
        
        if (EVP_PKEY_encrypt(ctx, out, &outlen, (unsigned char*)sessionKeyBytes.c_str(), sessionKeyBytes.length()) <= 0) {
             delete[] out; EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pubKey); return "Error: Encrypt";
        }

        std::string encryptedKeyHex = toHex(out, outlen);

        delete[] out;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);

        return encryptedKeyHex;
    }

    // --- SIGNATURES ---

    /// @brief Signs a message hash using RSA-SHA256.
    /// @param message The plaintext message to sign.
    /// @param privKeyPem The sender's Private Key (PEM).
    /// @return Digital Signature as Hex string.
    std::string signMessage(std::string message, std::string privKeyPem){
        EVP_PKEY* privKey = loadPrivateKey(privKeyPem);
        if (!privKey) return "Error: Load PrivKey";

        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, privKey) <= 0) return "Error: Init";

        if (EVP_DigestSignUpdate(mdctx, message.c_str(), message.length()) <= 0) return "Error: Update";

        size_t siglen;
        EVP_DigestSignFinal(mdctx, NULL, &siglen);

        unsigned char* sig = new unsigned char[siglen];
        if (EVP_DigestSignFinal(mdctx, sig, &siglen) <= 0) {
            delete[] sig; return "Error: Final";
        }

        std::string signatureHex = toHex(sig, siglen);

        delete[] sig;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(privKey);

        return signatureHex;
    }
};

// --- EXPORT TO JAVASCRIPT ---
EMSCRIPTEN_BINDINGS(my_module) {
    class_<PgpContext>("PgpContext")
        .constructor<>()
        .function("checkStatus", &PgpContext::checkStatus)
        .function("encrypt", &PgpContext::encrypt)
        .function("decrypt", &PgpContext::decrypt)
        .function("rsaEncryptKey", &PgpContext::rsaEncryptKey)
        .function("signMessage", &PgpContext::signMessage);
}