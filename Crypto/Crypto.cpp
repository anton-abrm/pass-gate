#include "Crypto.h"

#include <memory>
#include <algorithm>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

Base::ZBytes Crypto::compute_sha_256(std::span<const uint8_t> bytes) {

    Base::ZBytes result(SHA256_DIGEST_LENGTH);

    SHA256(bytes.data(), bytes.size(), result.data());

    return result;
}

Base::ZBytes Crypto::compute_sha_512(std::span<const uint8_t> bytes)
{
    Base::ZBytes result(SHA512_DIGEST_LENGTH);

    SHA512(bytes.data(), bytes.size(), result.data());

    return result;
}

Base::ZBytes
Crypto::compute_pbkdf2_hmac_sha512(std::span<const uint8_t> password,
                                   std::span<const uint8_t> salt,
                                   const std::size_t iteration_count,
                                   const std::size_t key_length) {

    const std::string_view digest = SN_sha512;

    OSSL_PARAM params[] = {
        { OSSL_KDF_PARAM_PASSWORD, OSSL_PARAM_OCTET_STRING, const_cast<unsigned char *>(password.data()), password.size(), 0},
        { OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING, const_cast<unsigned char *>(salt.data()), salt.size(), 0 },
        { OSSL_KDF_PARAM_ITER, OSSL_PARAM_UNSIGNED_INTEGER, const_cast<size_t *>(&iteration_count), sizeof(iteration_count), 0 },
        { OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, const_cast<char *>(digest.data()), digest.size(), 0 },
        { nullptr, 0, nullptr, 0, 0 }
    };

    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf(
            EVP_KDF_fetch(nullptr, OSSL_KDF_NAME_PBKDF2, nullptr),
            &EVP_KDF_free);

    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> kdf_ctx(
            EVP_KDF_CTX_new(kdf.get()),
            &EVP_KDF_CTX_free);

    Base::ZBytes result(key_length);

    if (EVP_KDF_derive(kdf_ctx.get(), result.data(), key_length, params) < 0)
        throw std::runtime_error("Unable to compute KDF");

    return result;
}

Base::ZBytes Crypto::compute_hkdf_hmac_sha512(std::span<const uint8_t> key,
                                                      std::span<const uint8_t> salt,
                                                      std::span<const uint8_t> info,
                                                      std::size_t key_length) {

    if (key_length > hkdf_hmac_sha512_max_key_length)
        throw std::invalid_argument("key_length is too large.");

    const std::string_view digest = SN_sha512;

    OSSL_PARAM params[] = {
            { OSSL_KDF_PARAM_KEY, OSSL_PARAM_OCTET_STRING, const_cast<unsigned char *>(key.data()),     key.size(),              0},
            { OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING, const_cast<unsigned char *>(salt.data()),   salt.size(),             0 },
            { OSSL_KDF_PARAM_INFO, OSSL_PARAM_OCTET_STRING, const_cast<unsigned char *>(info.data()),   info.size(),             0 },
            { OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, const_cast<char *>(digest.data()),         digest.size(),           0 },
            { nullptr, 0, nullptr,                                                                      0,                       0 }
    };

    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf(
            EVP_KDF_fetch(nullptr, OSSL_KDF_NAME_HKDF, nullptr),
            &EVP_KDF_free);

    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> kdf_ctx(
            EVP_KDF_CTX_new(kdf.get()),
            &EVP_KDF_CTX_free);

    Base::ZBytes result(key_length);

    if (EVP_KDF_derive(kdf_ctx.get(), result.data(), key_length, params) != 1)
        throw std::logic_error("Unable to compute KDF.");

    return result;
}

static constexpr std::size_t c_aes_256_block_size = 16;
static constexpr std::size_t c_aes_256_key_size = 32;

Base::ZBytes
Crypto::encrypt_aes_256_cbc(std::span<const uint8_t> key, std::span<const uint8_t> iv, std::span<const uint8_t> plain) {

    if (key.size() != c_aes_256_key_size)
        throw std::runtime_error("Invalid AES Key size.");

    if (iv.size() != c_aes_256_block_size)
        throw std::runtime_error("Invalid AES IV size.");

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
            EVP_CIPHER_CTX_new(),
            &EVP_CIPHER_CTX_free);

    if(1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()))
        throw std::runtime_error("Unable to initialize AES 256 CBC.");

    Base::ZBytes cipher(plain.size() + c_aes_256_block_size);

    int len{0};

    std::size_t output_size{0};

    if(1 != EVP_EncryptUpdate(ctx.get(), cipher.data(), &len, plain.data(), static_cast<int>(plain.size())))
        throw std::runtime_error("Unable to encrypt message using AES 256 CBC.");

    output_size += len;

    if(1 != EVP_EncryptFinal_ex(ctx.get(), cipher.data() + output_size, &len))
        throw std::runtime_error("Unable to encrypt message using AES 256 CBC.");

    output_size += len;

    cipher.resize(output_size);

    return cipher;
}



Base::ZBytes
Crypto::decrypt_aes_256_cbc(std::span<const uint8_t> key, std::span<const uint8_t> iv, std::span<const uint8_t> cipher) {

    if (key.size() != c_aes_256_key_size)
        throw std::runtime_error("Invalid AES Key size.");

    if (iv.size() != c_aes_256_block_size)
        throw std::runtime_error("Invalid AES IV size.");

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
            EVP_CIPHER_CTX_new(),
            &EVP_CIPHER_CTX_free);

    if(1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()))
        throw std::runtime_error("Unable to initialize AES 256 CBC.");

    Base::ZBytes plain(cipher.size() + c_aes_256_block_size);

    int len{0};

    std::size_t output_size{0};

    if(1 != EVP_DecryptUpdate(ctx.get(), plain.data(), &len, cipher.data(), static_cast<int>(cipher.size())))
        throw std::runtime_error("Unable to decrypt message using AES 256 CBC.");

    output_size += len;

    if(1 != EVP_DecryptFinal_ex(ctx.get(), plain.data() + output_size, &len))
        throw std::runtime_error("Unable to decrypt message using AES 256 CBC.");

    output_size += len;

    plain.resize(output_size);

    return plain;
}

Base::ZBytes Crypto::compute_hkdf_hmac_sha512_expand_only(
        std::span<const uint8_t> key,
        std::span<const uint8_t> info,
        std::size_t key_length)
{
    const char * digest = SN_sha512;
    const int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;

    OSSL_PARAM params[] = {
            { OSSL_KDF_PARAM_MODE,   OSSL_PARAM_INTEGER,      const_cast<int *>(&mode),                 sizeof(mode),   0 },
            { OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING,  const_cast<char *>(digest),               strlen(digest), 0 },
            { OSSL_KDF_PARAM_KEY,    OSSL_PARAM_OCTET_STRING, const_cast<unsigned char *>(key.data()),  key.size(),     0 },
            { OSSL_KDF_PARAM_INFO,   OSSL_PARAM_OCTET_STRING, const_cast<unsigned char *>(info.data()), info.size(),    0 },
            { nullptr,               0,                       nullptr,                                  0,              0 }
    };

    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf(
            EVP_KDF_fetch(nullptr, OSSL_KDF_NAME_HKDF, nullptr),
            &EVP_KDF_free);

    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> kdf_ctx(
            EVP_KDF_CTX_new(kdf.get()),
            &EVP_KDF_CTX_free);

    Base::ZBytes result(key_length);

    if (EVP_KDF_derive(kdf_ctx.get(), result.data(), key_length, params) != 1)
        throw std::logic_error("Unable to compute KDF.");

    return result;
}

