cmake_minimum_required(VERSION 3.10)
project(blackworm_openssl_crypto C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set optimization flags
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")

# Find OpenSSL (required)
find_package(OpenSSL 3.0 REQUIRED)

# Find Lean headers
# Prefer `lean --print-prefix`, which resolves the toolchain pinned by
# `lean-toolchain` (via elan) deterministically. Falling back to a glob over
# every installed elan toolchain is unsafe: if more than one toolchain is
# installed, it can silently pick headers from the wrong (e.g. much older)
# Lean version, producing a library that is ABI-incompatible with the
# `lean`/`lake`-built executables that actually load it.
find_program(LEAN_EXECUTABLE lean)
if(LEAN_EXECUTABLE)
    execute_process(
        COMMAND ${LEAN_EXECUTABLE} --print-prefix
        OUTPUT_VARIABLE LEAN_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(LEAN_PREFIX)
        find_path(LEAN_INCLUDE_DIR lean/lean.h
            HINTS ${LEAN_PREFIX}/include
            NO_DEFAULT_PATH
        )
    endif()
endif()

# Last-resort fallback if `lean` wasn't on PATH at all.
if(NOT LEAN_INCLUDE_DIR)
    find_path(LEAN_INCLUDE_DIR lean/lean.h
        HINTS
            /home/user/.elan/toolchains/*/include
            /usr/include
            /usr/local/include
            /opt/homebrew/include
        NO_DEFAULT_PATH
    )
endif()

# Final fallback
if(NOT LEAN_INCLUDE_DIR)
    message(WARNING "Could not find Lean headers, build may fail")
    set(LEAN_INCLUDE_DIR "/usr/include")
else()
    message(STATUS "Found Lean headers: ${LEAN_INCLUDE_DIR}")
endif()

message(STATUS "OpenSSL: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "Lean: ${LEAN_INCLUDE_DIR}")

# OpenSSL crypto library (shared)
add_library(openssl_crypto SHARED
    openssl_crypto.c
)

target_include_directories(openssl_crypto PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${LEAN_INCLUDE_DIR}
)

target_link_libraries(openssl_crypto
    ${OPENSSL_LIBRARIES}
)

# Add compiler warnings (without pedantic due to Lean header compatibility)
target_compile_options(openssl_crypto PRIVATE -Wall -Wextra)

# Installation
install(TARGETS openssl_crypto
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

# Optional: Create a static library version
add_library(openssl_crypto_static STATIC
    openssl_crypto.c
)

target_include_directories(openssl_crypto_static PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${LEAN_INCLUDE_DIR}
)

target_link_libraries(openssl_crypto_static
    ${OPENSSL_LIBRARIES}
)

target_compile_options(openssl_crypto_static PRIVATE -Wall -Wextra)

install(TARGETS openssl_crypto_static
    ARCHIVE DESTINATION lib
)

# Print summary
message(STATUS "Build Summary:")
message(STATUS "  OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Shared library: enabled")
message(STATUS "  Static library: enabled")
