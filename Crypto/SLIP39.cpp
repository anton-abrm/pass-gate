#include "SLIP39.h"

#include <algorithm>
#include <ranges>

#include "Crypto/Crypto.h"

static Base::ZBytes round_function(
        const uint8_t e,
        const uint16_t id,
        std::string_view passphrase,
        std::span<const uint8_t> r,
        const uint8_t i) {

    Base::ZBytes password;

    password.insert(password.end(), i);
    password.insert(password.end(), passphrase.begin(), passphrase.end());

    Base::ZBytes salt;

    const std::string prefix = "shamir";

    salt.insert(salt.end(), prefix.begin(), prefix.end());
    salt.insert(salt.end(), static_cast<uint8_t>(id >> 8));
    salt.insert(salt.end(), static_cast<uint8_t>(id >> 0));
    salt.insert(salt.end(), r.begin(), r.end());

    return Crypto::compute_pbkdf2_hmac_sha256(password, salt, 2500 << e, r.size());
}

static Base::ZBytes transform_master_secret(
        std::span<const uint8_t> bytes,
        const uint8_t e,
        const uint16_t id,
        std::string_view passphrase,
        bool decrypt)
{
    if (bytes.size() % 2 != 0)
        throw std::invalid_argument("Cipher size must be even.");

    Base::ZBytes l(bytes.begin(), bytes.begin() + static_cast<ssize_t>(bytes.size() / 2));
    Base::ZBytes r(bytes.begin() + static_cast<ssize_t>(bytes.size() / 2), bytes.end());

    constexpr uint8_t round_count = 4;

    for (uint8_t i = 0; i < round_count; i++)  {

        auto t = round_function(e, id, passphrase, r, decrypt
            ? round_count - i - 1
            : i);

        std::transform(t.begin(), t.end(), l.begin(), t.begin(), std::bit_xor());

        l = r;
        r = t;
    }

    Base::ZBytes res;

    res.insert(res.end(), r.begin(), r.end());
    res.insert(res.end(), l.begin(), l.end());

    return res;
}

Base::ZBytes SLIP39::encrypt_master_secret(
        std::span<const uint8_t> plain,
        const uint8_t e,
        const uint16_t id,
        std::string_view passphrase)
{
    return transform_master_secret(plain, e, id, passphrase, false);
}

Base::ZBytes SLIP39::decrypt_master_secret(
        std::span<const uint8_t> cipher,
        const uint8_t e,
        const uint16_t id,
        std::string_view passphrase)
{
    return transform_master_secret(cipher, e, id, passphrase, true);
}

