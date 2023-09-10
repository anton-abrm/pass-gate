#pragma once

#include <memory>

#include "Base/ZVector.h"
#include "Core/RandomNumberGenerator.h"


namespace Core {

    class BufferedRandomNumberGenerator final : public virtual Core::RandomNumberGenerator {

    public:
        explicit BufferedRandomNumberGenerator(std::shared_ptr<Core::RandomNumberGenerator> rng, std::size_t buffer_size);

        void generate_random(std::span<uint8_t> out) override;

    private:
        const std::shared_ptr<Core::RandomNumberGenerator> m_rng;
        Base::ZBytes::iterator m_begin;
        Base::ZBytes::iterator m_end;
        Base::ZBytes m_buffer;
    };
}
