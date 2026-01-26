#!/bin/bash
# Stop on error
set -e

# Make a build folder
mkdir -p build
cd build

# Run CMake using the Emscripten toolchain
emcmake cmake ..

# Compile the bridge
emmake make

echo "Build Successful! Files secure_chat.js and .wasm are in crypto/build/"