#pragma once

#include <cstdint>
#include <span>

namespace Core {
    class ByteSplitter final {
    public:
        explicit ByteSplitter(std::span<const uint8_t> buffer);
        std::span<const uint8_t> next(size_t size);
        std::span<const uint8_t> last();
    private:
        const std::span<const uint8_t> m_buffer;
        std::size_t m_offset {0};
    };
}