#pragma once

#include "RandomNumberGenerator.h"

namespace Core {

    class MemoryRandomNumberGenerator final : public virtual Core::RandomNumberGenerator {

    public:
        explicit MemoryRandomNumberGenerator(std::span<const uint8_t> buffer):
            m_buffer{buffer.begin(), buffer.end()},
            m_index{0} {
        }

        void generate_random(std::span<uint8_t> span) override;

    private:
        Base::ZBytes m_buffer;
        std::size_t m_index;
    };
}
