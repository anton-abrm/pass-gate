#include "BIP39EntropySourceV2.h"
#include "BIP39/BIP39.h"

Core::BIP39EntropySourceV2::BIP39EntropySourceV2(std::string_view mnemonic, std::string_view info)
    : m_mnemonic{ mnemonic },
     m_info { info }
{
}

Base::ZBytes Core::BIP39EntropySourceV2::get_seed(std::string_view nonce, const std::size_t size) const
{
    if (size > Crypto::hkdf_hmac_sha512_max_key_length)
        throw std::invalid_argument("The size of the requested bytes is too large.");

    const auto seed = BIP39::mnemonic_to_seed(m_mnemonic, nonce);

    if (!seed)
        throw std::runtime_error("Mnemonic is not valid");

    const auto info = std::span<const uint8_t>{
            reinterpret_cast<const uint8_t *>(m_info.data()), m_info.size() };

    return Crypto::compute_hkdf_hmac_sha512_expand_only(seed.value(), info, size);
}

std::size_t Core::BIP39EntropySourceV2::max_seed_size() const
{
    return Crypto::hkdf_hmac_sha512_max_key_length;
}
