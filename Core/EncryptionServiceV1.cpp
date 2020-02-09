#include "EncryptionServiceV1.h"

#include "Crypto/Crypto.h"

Core::EncryptionServiceV1::EncryptionServiceV1(
        std::shared_ptr<const Core::EntropySource> entropy_source,
        std::shared_ptr<const Core::RandomNumberGenerator> rng,
        std::string_view passphrase)
        : m_entropy_source{std::move(entropy_source)},
          m_rng {std::move(rng)},
          m_passphrase{passphrase}
{
    if (!m_entropy_source)
        throw std::invalid_argument("entropy_source is null.");

    if (!m_rng)
        throw std::invalid_argument("rng is null.");
}

Base::ZBytes Core::EncryptionServiceV1::encrypt(
        std::string_view plain) const
{
    const auto seed = m_entropy_source->get_seed(m_passphrase, 48);

    return Crypto::encrypt_aes_256_cbc(
            std::span<const uint8_t>(seed.data(), 32),
            std::span<const uint8_t>(seed.data() + 32, 16),
            std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(plain.data()), plain.size()));
}

Base::ZString Core::EncryptionServiceV1::decrypt(std::span<const uint8_t> body) const {

    const auto seed = m_entropy_source->get_seed(m_passphrase, 48);

    const auto bytes = Crypto::decrypt_aes_256_cbc(
            std::span<const uint8_t>(seed.data(), 32),
            std::span<const uint8_t>(seed.data() + 32, 16),
            body);

    return {bytes.begin(), bytes.end()};
}