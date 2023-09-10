#include "BIP39EntropySource.h"
#include "Crypto/BIP39.h"

Core::BIP39EntropySource::BIP39EntropySource(std::string_view mnemonic)
    : m_mnemonic{ mnemonic }
{
}

Base::ZBytes Core::BIP39EntropySource::get_seed(std::string_view nonce, const std::size_t size)
{
    if (size > BIP39::seed_size)
        throw std::invalid_argument("The size of the requested bytes is too large.");

    const auto optional_seed = BIP39::mnemonic_to_seed(m_mnemonic, nonce);

    if (!optional_seed)
        throw std::runtime_error("Mnemonic is not valid");

    auto result = optional_seed.value();

    result.resize(size);

    return result;
}

std::size_t Core::BIP39EntropySource::max_seed_size() const
{
    return BIP39::seed_size;
}
