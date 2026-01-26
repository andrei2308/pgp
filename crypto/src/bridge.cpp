#include <emscripten/bind.h>
#include <openssl/evp.h>
#include <string>

using namespace emscripten;

class PgpContext {
public:
    PgpContext() {}

    std::string checkStatus() {
        const EVP_CIPHER* cipher = EVP_aes_256_gcm();
        if (cipher) {
            return "OpenSSL 3.1 is Loaded & Ready! (AES-256-GCM available)";
        } else {
            return "Error: OpenSSL failed to load.";
        }
    }

    std::string encrypt(std::string input) {
        return "Encrypted: " + input;
    }
};

// expose to js
EMSCRIPTEN_BINDINGS(my_module) {
    class_<PgpContext>("PgpContext")
        .constructor<>()
        .function("checkStatus", &PgpContext::checkStatus)
        .function("encrypt", &PgpContext::encrypt);
}