#include "RandomEntropySource.h"

#include <limits>

Base::ZBytes Core::RandomEntropySource::get_seed(std::string_view nonce, const std::size_t size) const
{
    return m_rng->generate_random(size);
}

Core::RandomEntropySource::RandomEntropySource(std::shared_ptr<const Core::RandomNumberGenerator> rng)
   : m_rng {std::move(rng)}
{
    if (!m_rng)
        throw std::invalid_argument("rng is null.");
}

std::size_t Core::RandomEntropySource::max_seed_size() const
{
    return std::numeric_limits<size_t>::max();
}
