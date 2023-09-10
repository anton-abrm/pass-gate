#pragma once

#include <memory>

#include "RandomNumberGenerator.h"
#include "Core/EntropySource.h"

namespace Core
{
    class RandomEntropySource : public virtual Core::EntropySource
    {

    public:

        explicit RandomEntropySource(std::shared_ptr<Core::RandomNumberGenerator> rng);

        [[nodiscard]] Base::ZBytes get_seed(std::string_view nonce, std::size_t size) override;
        [[nodiscard]] std::size_t max_seed_size() const override;

    private:
        const std::shared_ptr<Core::RandomNumberGenerator> m_rng;
    };
}
