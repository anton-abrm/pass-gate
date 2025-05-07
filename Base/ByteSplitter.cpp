#include "ByteSplitter.h"

#include <stdexcept>

Core::ByteSplitter::ByteSplitter(std::span<const uint8_t> buffer)
    : m_buffer(buffer) {
}

std::span<const uint8_t> Core::ByteSplitter::next(const size_t size) {

    if (size > m_buffer.size() - m_offset)
        throw std::invalid_argument("size is greater than the remaining buffer");

    const auto span = std::span { m_buffer.data() + m_offset, size };
    m_offset += size;
    return span;
}

std::span<const uint8_t> Core::ByteSplitter::last() {
   return next(m_buffer.size() - m_offset);
}
