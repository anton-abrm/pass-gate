#pragma once

#include <memory>

#include "Core/RandomNumberGenerator.h"

namespace PKI {
    class HostRandomNumberGenerator final : public virtual Core::RandomNumberGenerator {

    private:
        explicit HostRandomNumberGenerator();

    public:

        void generate_random(std::span<uint8_t> out) override;

        static std::shared_ptr<HostRandomNumberGenerator> instance();
    };
}
