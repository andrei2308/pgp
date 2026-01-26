cmake_minimum_required(VERSION 3.10)
project(SecureChatWasm)

set(CMAKE_CXX_STANDARD 17)

# 1. Setup paths
set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/openssl")
include_directories(${OPENSSL_ROOT_DIR}/include)

# 2. Add our bridge file
add_executable(secure_chat src/bridge.cpp)

# 3. Link the OpenSSL libraries
target_link_libraries(secure_chat 
    ${OPENSSL_ROOT_DIR}/libssl.a 
    ${OPENSSL_ROOT_DIR}/libcrypto.a
)

# 4. Emscripten-specific settings
set_target_properties(secure_chat PROPERTIES LINK_FLAGS 
    "--bind \
     -s MODULARIZE=1 \
     -s 'EXPORT_NAME=\"PGPCore\"' \
     -s EXPORTED_RUNTIME_METHODS='[\"ccall\", \"cwrap\"]' \
     -s ALLOW_MEMORY_GROWTH=1 \
     -s WASM=1 \
     -s SINGLE_FILE=0"
)