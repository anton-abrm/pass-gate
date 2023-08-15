#pragma once

#include <memory>

#include "Core/RandomNumberGenerator.h"

namespace PKI {
    class HostRandomNumberGenerator final : public virtual Core::RandomNumberGenerator {

    private:
        explicit HostRandomNumberGenerator();

    public:

        [[nodiscard]] Base::ZBytes generate_random(std::size_t length) const override;

        static std::shared_ptr<HostRandomNumberGenerator> instance();
    };
}
