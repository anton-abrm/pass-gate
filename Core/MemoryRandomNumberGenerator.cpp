#include "MemoryRandomNumberGenerator.h"

void Core::MemoryRandomNumberGenerator::generate_random(std::span<uint8_t> span) {

    if (span.size() > m_buffer.size() - m_index) {
        throw std::logic_error("Not enough entropy.");
    }

    std::copy(m_buffer.begin() + static_cast<Base::ZBytes::difference_type>(m_index),
              m_buffer.begin() + static_cast<Base::ZBytes::difference_type>(m_index + span.size()),
              span.begin());

    m_index += span.size();

}
