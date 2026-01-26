#include <emscripten/bind.h>
#include <openssl/evp.h>
#include <string>
#include <sstream>
#include <iomanip>

using namespace emscripten;

class PgpContext {
public:
    PgpContext() {}

    std::string toHex(const unsigned char* data, int len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < len; ++i) {
            ss << std::setw(2) << (int)data[i];
        }
        return ss.str();
    }

    std::string checkStatus() {
        const EVP_CIPHER* cipher = EVP_aes_256_gcm();
        if (cipher) {
            return "OpenSSL 3.1 is Loaded & Ready! (AES-256-GCM available)";
        } else {
            return "Error: OpenSSL failed to load.";
        }
    }

    std::string encrypt(std::string input) {
        const EVP_CIPHER* cipher = EVP_aes_128_cbc();
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_set_key_length(ctx, 128);
        
        unsigned char key[16] = {0};
        unsigned char iv[16] = {0};
        
        EVP_CipherInit(ctx, cipher, key, iv, 1);
        
        unsigned char out[1024];
        int outlen;
        int finalLen;
        EVP_CipherUpdate(ctx, out, &outlen, (unsigned char*) input.c_str(), input.length());
        
        EVP_CipherFinal(ctx, out + outlen, &finalLen);
        
        EVP_CIPHER_CTX_free(ctx);
       
        return toHex(out, outlen + finalLen);
    }
};

// expose to js
EMSCRIPTEN_BINDINGS(my_module) {
    class_<PgpContext>("PgpContext")
        .constructor<>()
        .function("checkStatus", &PgpContext::checkStatus)
        .function("encrypt", &PgpContext::encrypt);
}