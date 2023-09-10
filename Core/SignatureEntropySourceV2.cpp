#include "SignatureEntropySourceV2.h"

#include <locale>
#include <codecvt>

#include "Crypto/Crypto.h"

Base::ZBytes Core::SignatureEntropySourceV2::get_seed(std::string_view nonce, std::size_t size)
{
    const auto sign = m_provider->sign(
            m_id, { reinterpret_cast<const uint8_t *>(nonce.data()), nonce.size() });

    return Crypto::compute_hkdf_hmac_sha512(
            sign,
            { reinterpret_cast<const uint8_t *>(nonce.data()), nonce.size() },
            { reinterpret_cast<const uint8_t *>(m_info.data()), m_info.size() },
            size);
}

Core::SignatureEntropySourceV2::SignatureEntropySourceV2(
        const std::shared_ptr<const Core::PKIProvider> &provider,
        std::span<const uint8_t> id,
        std::string_view info)
    : m_provider { provider },
      m_id { id.begin(), id.end() },
      m_info {info}
{
    if (!provider)
        throw std::invalid_argument("provider is null.");
}

std::size_t Core::SignatureEntropySourceV2::max_seed_size() const
{
    return Crypto::hkdf_hmac_sha512_max_key_length;
}
