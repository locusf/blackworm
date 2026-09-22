#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdlib.h>
#include <lean/lean.h>

// SHA-256 Hash
LEAN_EXPORT lean_obj_res openssl_sha256_hash(b_lean_obj_arg data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL) {
        lean_internal_panic_out_of_memory();
    }

    size_t data_len = lean_sarray_size(data);
    unsigned char *data_ptr = (unsigned char *)lean_sarray_cptr(data);

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(ctx);
        lean_internal_panic("SHA256 initialization failed");
    }
    EVP_DigestUpdate(ctx, data_ptr, data_len);
    if (!EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
        EVP_MD_CTX_free(ctx);
        lean_internal_panic("SHA256 finalization failed");
    }
    EVP_MD_CTX_free(ctx);

    lean_object *result = lean_alloc_sarray(1, hash_len, hash_len);
    memcpy((void *)lean_sarray_cptr(result), hash, hash_len);
    return lean_io_result_mk_ok(result);
}

// SHA3-256 Hash
LEAN_EXPORT lean_obj_res openssl_sha3_256_hash(b_lean_obj_arg data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL) {
        lean_internal_panic_out_of_memory();
    }

    size_t data_len = lean_sarray_size(data);
    unsigned char *data_ptr = (unsigned char *)lean_sarray_cptr(data);

    if (!EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL)) {
        EVP_MD_CTX_free(ctx);
        lean_internal_panic("SHA3-256 initialization failed");
    }
    EVP_DigestUpdate(ctx, data_ptr, data_len);
    if (!EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
        EVP_MD_CTX_free(ctx);
        lean_internal_panic("SHA3-256 finalization failed");
    }
    EVP_MD_CTX_free(ctx);

    lean_object *result = lean_alloc_sarray(1, hash_len, hash_len);
    memcpy((void *)lean_sarray_cptr(result), hash, hash_len);
    return lean_io_result_mk_ok(result);
}

// AES-256-ECB Encrypt
LEAN_EXPORT lean_obj_res openssl_aes_256_ecb_encrypt(b_lean_obj_arg key, b_lean_obj_arg plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        lean_internal_panic_out_of_memory();
    }

    unsigned char *out = malloc(lean_sarray_size(plaintext) + 16);
    if (out == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic_out_of_memory();
    }

    int len = 0, ciphertext_len;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL,
                           (unsigned char *)lean_sarray_cptr(key), NULL)) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("AES-256-ECB initialization failed");
    }
    EVP_EncryptUpdate(ctx, out, &len,
                      (unsigned char *)lean_sarray_cptr(plaintext),
                      lean_sarray_size(plaintext));
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, out + len, &len)) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("AES-256-ECB encryption finalization failed");
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    lean_object *result = lean_alloc_sarray(1, ciphertext_len, ciphertext_len);
    memcpy((void *)lean_sarray_cptr(result), out, ciphertext_len);
    free(out);
    return lean_io_result_mk_ok(result);
}

// AES-256-ECB Decrypt
LEAN_EXPORT lean_obj_res openssl_aes_256_ecb_decrypt(b_lean_obj_arg key, b_lean_obj_arg ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        lean_internal_panic_out_of_memory();
    }

    unsigned char *out = malloc(lean_sarray_size(ciphertext) + 16);
    if (out == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic_out_of_memory();
    }

    int len = 0, plaintext_len;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL,
                           (unsigned char *)lean_sarray_cptr(key), NULL)) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("AES-256-ECB decryption initialization failed");
    }
    EVP_DecryptUpdate(ctx, out, &len,
                      (unsigned char *)lean_sarray_cptr(ciphertext),
                      lean_sarray_size(ciphertext));
    plaintext_len = len;
    if (!EVP_DecryptFinal_ex(ctx, out + len, &len)) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("AES-256-ECB decryption finalization failed");
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    lean_object *result = lean_alloc_sarray(1, plaintext_len, plaintext_len);
    memcpy((void *)lean_sarray_cptr(result), out, plaintext_len);
    free(out);
    return lean_io_result_mk_ok(result);
}

// AES-256-CBC Encrypt
LEAN_EXPORT lean_obj_res openssl_aes_256_cbc_encrypt(b_lean_obj_arg key, b_lean_obj_arg iv, b_lean_obj_arg plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        lean_internal_panic_out_of_memory();
    }

    unsigned char *out = malloc(lean_sarray_size(plaintext) + 16);
    if (out == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic_out_of_memory();
    }

    int len = 0, ciphertext_len;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                           (unsigned char *)lean_sarray_cptr(key),
                           (unsigned char *)lean_sarray_cptr(iv))) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("AES-256-CBC encryption initialization failed");
    }
    EVP_EncryptUpdate(ctx, out, &len,
                      (unsigned char *)lean_sarray_cptr(plaintext),
                      lean_sarray_size(plaintext));
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, out + len, &len)) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("AES-256-CBC encryption finalization failed");
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    lean_object *result = lean_alloc_sarray(1, ciphertext_len, ciphertext_len);
    memcpy((void *)lean_sarray_cptr(result), out, ciphertext_len);
    free(out);
    return lean_io_result_mk_ok(result);
}

// AES-256-CBC Decrypt
LEAN_EXPORT lean_obj_res openssl_aes_256_cbc_decrypt(b_lean_obj_arg key, b_lean_obj_arg iv, b_lean_obj_arg ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        lean_internal_panic_out_of_memory();
    }

    unsigned char *out = malloc(lean_sarray_size(ciphertext) + 16);
    if (out == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic_out_of_memory();
    }

    int len = 0, plaintext_len;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                           (unsigned char *)lean_sarray_cptr(key),
                           (unsigned char *)lean_sarray_cptr(iv))) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("AES-256-CBC decryption initialization failed");
    }
    EVP_DecryptUpdate(ctx, out, &len,
                      (unsigned char *)lean_sarray_cptr(ciphertext),
                      lean_sarray_size(ciphertext));
    plaintext_len = len;
    if (!EVP_DecryptFinal_ex(ctx, out + len, &len)) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("AES-256-CBC decryption finalization failed");
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    lean_object *result = lean_alloc_sarray(1, plaintext_len, plaintext_len);
    memcpy((void *)lean_sarray_cptr(result), out, plaintext_len);
    free(out);
    return lean_io_result_mk_ok(result);
}

// AES-256-GCM Encrypt returns (ciphertext, tag)
LEAN_EXPORT lean_obj_res openssl_aes_256_gcm_encrypt(b_lean_obj_arg key, b_lean_obj_arg iv,
                                                     b_lean_obj_arg plaintext, b_lean_obj_arg aad) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        lean_internal_panic_out_of_memory();
    }

    unsigned char *ciphertext = malloc(lean_sarray_size(plaintext) + 16);
    if (ciphertext == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic_out_of_memory();
    }

    unsigned char tag[16];
    int len = 0, ciphertext_len;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
                           (unsigned char *)lean_sarray_cptr(key),
                           (unsigned char *)lean_sarray_cptr(iv))) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("AES-256-GCM encryption initialization failed");
    }

    if (lean_sarray_size(aad) > 0) {
        EVP_EncryptUpdate(ctx, NULL, &len,
                         (unsigned char *)lean_sarray_cptr(aad),
                         lean_sarray_size(aad));
    }

    EVP_EncryptUpdate(ctx, ciphertext, &len,
                      (unsigned char *)lean_sarray_cptr(plaintext),
                      lean_sarray_size(plaintext));
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("AES-256-GCM encryption finalization failed");
    }
    ciphertext_len += len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("AES-256-GCM tag retrieval failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    lean_object *c_obj = lean_alloc_sarray(1, ciphertext_len, ciphertext_len);
    memcpy((void *)lean_sarray_cptr(c_obj), ciphertext, ciphertext_len);
    lean_object *t_obj = lean_alloc_sarray(1, 16, 16);
    memcpy((void *)lean_sarray_cptr(t_obj), tag, 16);

    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, c_obj);
    lean_ctor_set(pair, 1, t_obj);

    free(ciphertext);
    return lean_io_result_mk_ok(pair);
}

// AES-256-GCM Decrypt returns Option ByteArray
LEAN_EXPORT lean_obj_res openssl_aes_256_gcm_decrypt(b_lean_obj_arg key, b_lean_obj_arg iv,
                                                     b_lean_obj_arg ciphertext, b_lean_obj_arg tag,
                                                     b_lean_obj_arg aad) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        lean_internal_panic_out_of_memory();
    }

    unsigned char *plaintext = malloc(lean_sarray_size(ciphertext) + 16);
    if (plaintext == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic_out_of_memory();
    }

    int len = 0, plaintext_len;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
                           (unsigned char *)lean_sarray_cptr(key),
                           (unsigned char *)lean_sarray_cptr(iv))) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return lean_io_result_mk_ok(lean_box(0));  // None
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, lean_sarray_size(tag),
                            (unsigned char *)lean_sarray_cptr(tag))) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return lean_io_result_mk_ok(lean_box(0));  // None
    }

    if (lean_sarray_size(aad) > 0) {
        EVP_DecryptUpdate(ctx, NULL, &len,
                         (unsigned char *)lean_sarray_cptr(aad),
                         lean_sarray_size(aad));
    }

    EVP_DecryptUpdate(ctx, plaintext, &len,
                      (unsigned char *)lean_sarray_cptr(ciphertext),
                      lean_sarray_size(ciphertext));
    plaintext_len = len;

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        free(plaintext);
        return lean_io_result_mk_ok(lean_box(0));  // None
    }

    lean_object *p_obj = lean_alloc_sarray(1, plaintext_len, plaintext_len);
    memcpy((void *)lean_sarray_cptr(p_obj), plaintext, plaintext_len);
    free(plaintext);

    lean_object *some = lean_alloc_ctor(1, 1, 0);
    lean_ctor_set(some, 0, p_obj);
    return lean_io_result_mk_ok(some);  // Some plaintext
}

// ChaCha20-Poly1305 Encrypt
LEAN_EXPORT lean_obj_res openssl_chacha20_poly1305_encrypt(b_lean_obj_arg key, b_lean_obj_arg nonce,
                                                           b_lean_obj_arg plaintext, b_lean_obj_arg aad) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        lean_internal_panic_out_of_memory();
    }

    unsigned char *ciphertext = malloc(lean_sarray_size(plaintext) + 16);
    if (ciphertext == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic_out_of_memory();
    }

    unsigned char tag[16];
    int len = 0, ciphertext_len;

    if (!EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL,
                           (unsigned char *)lean_sarray_cptr(key),
                           (unsigned char *)lean_sarray_cptr(nonce))) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("ChaCha20-Poly1305 encryption initialization failed");
    }

    if (lean_sarray_size(aad) > 0) {
        EVP_EncryptUpdate(ctx, NULL, &len,
                         (unsigned char *)lean_sarray_cptr(aad),
                         lean_sarray_size(aad));
    }

    EVP_EncryptUpdate(ctx, ciphertext, &len,
                      (unsigned char *)lean_sarray_cptr(plaintext),
                      lean_sarray_size(plaintext));
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("ChaCha20-Poly1305 encryption finalization failed");
    }
    ciphertext_len += len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic("ChaCha20-Poly1305 tag retrieval failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    lean_object *c_obj = lean_alloc_sarray(1, ciphertext_len, ciphertext_len);
    memcpy((void *)lean_sarray_cptr(c_obj), ciphertext, ciphertext_len);
    lean_object *t_obj = lean_alloc_sarray(1, 16, 16);
    memcpy((void *)lean_sarray_cptr(t_obj), tag, 16);

    lean_object *pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, c_obj);
    lean_ctor_set(pair, 1, t_obj);

    free(ciphertext);
    return lean_io_result_mk_ok(pair);
}

// ChaCha20-Poly1305 Decrypt
LEAN_EXPORT lean_obj_res openssl_chacha20_poly1305_decrypt(b_lean_obj_arg key, b_lean_obj_arg nonce,
                                                           b_lean_obj_arg ciphertext, b_lean_obj_arg tag,
                                                           b_lean_obj_arg aad) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        lean_internal_panic_out_of_memory();
    }

    unsigned char *plaintext = malloc(lean_sarray_size(ciphertext) + 16);
    if (plaintext == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        lean_internal_panic_out_of_memory();
    }

    int len = 0, plaintext_len;

    if (!EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL,
                           (unsigned char *)lean_sarray_cptr(key),
                           (unsigned char *)lean_sarray_cptr(nonce))) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return lean_io_result_mk_ok(lean_box(0));  // None
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, lean_sarray_size(tag),
                            (unsigned char *)lean_sarray_cptr(tag))) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return lean_io_result_mk_ok(lean_box(0));  // None
    }

    if (lean_sarray_size(aad) > 0) {
        EVP_DecryptUpdate(ctx, NULL, &len,
                         (unsigned char *)lean_sarray_cptr(aad),
                         lean_sarray_size(aad));
    }

    EVP_DecryptUpdate(ctx, plaintext, &len,
                      (unsigned char *)lean_sarray_cptr(ciphertext),
                      lean_sarray_size(ciphertext));
    plaintext_len = len;

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        free(plaintext);
        return lean_io_result_mk_ok(lean_box(0));  // None
    }

    lean_object *p_obj = lean_alloc_sarray(1, plaintext_len, plaintext_len);
    memcpy((void *)lean_sarray_cptr(p_obj), plaintext, plaintext_len);
    free(plaintext);

    lean_object *some = lean_alloc_ctor(1, 1, 0);
    lean_ctor_set(some, 0, p_obj);
    return lean_io_result_mk_ok(some);  // Some plaintext
}

// Simpler HKDF implementation using EVP_HMAC
// HKDF = Extract-and-Expand pseudorandom key derivation function
// Following RFC 5869

// HKDF with SHA-256
LEAN_EXPORT lean_obj_res openssl_hkdf_sha256(b_lean_obj_arg salt, b_lean_obj_arg ikm,
                                            b_lean_obj_arg info, lean_obj_arg length) {
    size_t out_len = lean_unbox(length);
    unsigned char *okm = malloc(out_len);

    if (okm == NULL) {
        lean_internal_panic_out_of_memory();
    }

    unsigned char prk[EVP_MAX_MD_SIZE];
    unsigned int prk_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL) {
        free(okm);
        lean_internal_panic_out_of_memory();
    }

    // Extract phase: PRK = HMAC-Hash(salt, IKM)
    unsigned char *salt_ptr = (unsigned char *)lean_sarray_cptr(salt);
    size_t salt_len = lean_sarray_size(salt);

    // If salt is empty, use hash-length zeros
    unsigned char default_salt[EVP_MAX_MD_SIZE] = {0};
    if (salt_len == 0) {
        salt_len = EVP_MAX_MD_SIZE;
        salt_ptr = default_salt;
    }

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(ctx);
        free(okm);
        lean_internal_panic("HKDF extract init failed");
    }

    HMAC_CTX *hmac = HMAC_CTX_new();
    if (hmac == NULL) {
        EVP_MD_CTX_free(ctx);
        free(okm);
        lean_internal_panic_out_of_memory();
    }

    if (!HMAC_Init_ex(hmac, salt_ptr, salt_len, EVP_sha256(), NULL)) {
        HMAC_CTX_free(hmac);
        EVP_MD_CTX_free(ctx);
        free(okm);
        lean_internal_panic("HMAC init failed");
    }

    HMAC_Update(hmac, (unsigned char *)lean_sarray_cptr(ikm), lean_sarray_size(ikm));
    HMAC_Final(hmac, prk, &prk_len);

    // Expand phase: T = T(1) | T(2) | T(3) | ... where T(N) = HMAC-Hash(PRK, T(N-1) | info | N)
    unsigned char *out_pos = okm;
    size_t remaining = out_len;
    unsigned char t[EVP_MAX_MD_SIZE] = {0};
    unsigned int t_len = 0;
    unsigned char counter = 1;

    while (remaining > 0) {
        if (!HMAC_Init_ex(hmac, prk, prk_len, EVP_sha256(), NULL)) {
            HMAC_CTX_free(hmac);
            EVP_MD_CTX_free(ctx);
            free(okm);
            lean_internal_panic("HKDF expand init failed");
        }

        if (t_len > 0) {
            HMAC_Update(hmac, t, t_len);
        }
        HMAC_Update(hmac, (unsigned char *)lean_sarray_cptr(info), lean_sarray_size(info));
        HMAC_Update(hmac, &counter, 1);
        HMAC_Final(hmac, t, &t_len);

        size_t copy_len = (remaining < t_len) ? remaining : t_len;
        memcpy(out_pos, t, copy_len);
        out_pos += copy_len;
        remaining -= copy_len;
        counter++;
    }

    HMAC_CTX_free(hmac);
    EVP_MD_CTX_free(ctx);

    lean_object *result = lean_alloc_sarray(1, out_len, out_len);
    memcpy((void *)lean_sarray_cptr(result), okm, out_len);
    free(okm);
    return lean_io_result_mk_ok(result);
}

// PBKDF2 with SHA-256
LEAN_EXPORT lean_obj_res openssl_pbkdf2_sha256(b_lean_obj_arg password, b_lean_obj_arg salt,
                                              lean_obj_arg iterations, lean_obj_arg key_len) {
    size_t klen = lean_unbox(key_len);
    unsigned char *key = malloc(klen);

    if (key == NULL) {
        lean_internal_panic_out_of_memory();
    }

    int ret = PKCS5_PBKDF2_HMAC((char *)lean_sarray_cptr(password), lean_sarray_size(password),
                               (unsigned char *)lean_sarray_cptr(salt), lean_sarray_size(salt),
                               lean_unbox(iterations), EVP_sha256(),
                               klen, key);

    if (ret <= 0) {
        free(key);
        lean_internal_panic("PBKDF2 derivation failed");
    }

    lean_object *result = lean_alloc_sarray(1, klen, klen);
    memcpy((void *)lean_sarray_cptr(result), key, klen);
    free(key);
    return lean_io_result_mk_ok(result);
}
