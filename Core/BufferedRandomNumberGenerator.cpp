#include "BufferedRandomNumberGenerator.h"

#include <algorithm>

Core::BufferedRandomNumberGenerator::BufferedRandomNumberGenerator(
        std::shared_ptr<Core::RandomNumberGenerator> rng,
        std::size_t buffer_size)
            : m_rng { std::move(rng) },
              m_buffer (buffer_size) {

    m_begin = m_buffer.begin();
    m_end = m_buffer.begin();
}

void Core::BufferedRandomNumberGenerator::generate_random(std::span<uint8_t> out) {

    auto out_begin = out.begin();
    auto out_end = out.end();

    while (true) {

        auto in_remaining = m_end - m_begin;
        auto out_remaining = out_end - out_begin;

        if (out_remaining <= in_remaining) {
            std::copy_n(m_begin, out_remaining, out_begin);
            m_begin += out_remaining;
            break;
        }

        out_begin = std::copy_n(m_begin, in_remaining, out_begin);

        m_rng->generate_random(m_buffer);

        m_begin = m_buffer.begin();
        m_end = m_buffer.end();
    }
}