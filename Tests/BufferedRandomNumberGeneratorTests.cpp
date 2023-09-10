#include <vector>
#include <iostream>

#include "gtest/gtest.h"

#include "Base/Encoding.h"
#include "Core/BufferedRandomNumberGenerator.h"

namespace {

    class RNG final : public virtual Core::RandomNumberGenerator {
    public:

        void generate_random(std::span<uint8_t> span) override {

            if (span.size() > 0xF)
                throw std::invalid_argument("out size is too large.");

            if (m_counter > 0xF)
                throw std::logic_error("reached the end of the stream.");

            for (std::size_t i = 0; i < span.size(); ++i) {
                span[i] = m_counter << 4 | (i + 1);
            }

            m_counter++;
        }

    private:
        uint8_t m_counter {1};
    };
}

static void generate_random_test(
        const size_t buffer_size,
        const size_t bytes_per_iteration,
        const size_t iteration_count,
        const std::string &expected_random_hex
) {

    const auto expected_random = Base::Encoding::decode_hex_any(expected_random_hex);

    Core::BufferedRandomNumberGenerator rng(std::make_shared<RNG>(), buffer_size);

    Base::ZBytes result;

    for (size_t i = 0; i < iteration_count; ++i) {
        std::vector<uint8_t> v(bytes_per_iteration);
        rng.generate_random(v);
        result.insert(result.end(), v.begin(), v.end());
    }

    EXPECT_EQ(result, expected_random);
}


TEST(BufferedRandomNumberGenerator, generate_random) {

    generate_random_test(0, 0, 0, "");
    generate_random_test(1, 1, 1, "11");
    generate_random_test(3, 2, 2, "11121321");
    generate_random_test(3, 2, 3, "111213212223");
}