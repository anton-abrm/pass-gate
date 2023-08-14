#pragma once

#include <vector>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "Base/ZVector.h"

namespace Crypto {

    const std::size_t sha512_length {64};
    const std::size_t hkdf_hmac_sha512_max_key_length {255 * sha512_length};

    Base::ZBytes compute_sha_256(
            std::span<const uint8_t> bytes);

    Base::ZBytes compute_sha_512(
            std::span<const uint8_t> bytes);

    Base::ZBytes compute_pbkdf2_hmac_sha512(
            std::span<const uint8_t> password,
            std::span<const uint8_t> salt,
            std::size_t iteration_count,
            std::size_t key_length);

    Base::ZBytes compute_hkdf_hmac_sha512(
            std::span<const uint8_t> key,
            std::span<const uint8_t> salt,
            std::span<const uint8_t> info,
            std::size_t key_length);

    Base::ZBytes compute_hkdf_hmac_sha512_expand_only(
            std::span<const uint8_t> key,
            std::span<const uint8_t> info,
            std::size_t key_length);

    Base::ZBytes encrypt_aes_256_cbc(
            std::span<const uint8_t> key,
            std::span<const uint8_t> iv,
            std::span<const uint8_t> plain);

    Base::ZBytes decrypt_aes_256_cbc(
            std::span<const uint8_t> key,
            std::span<const uint8_t> iv,
            std::span<const uint8_t> cipher);

    Base::ZBytes encrypt_aes_256_gcm(
            std::span<const uint8_t> key,
            std::span<const uint8_t> iv,
            std::span<const uint8_t> plain,
            Base::ZBytes &tag);

    Base::ZBytes decrypt_aes_256_gcm(
            std::span<const uint8_t> key,
            std::span<const uint8_t> iv,
            std::span<const uint8_t> cipher,
            std::span<const uint8_t> tag);
}
