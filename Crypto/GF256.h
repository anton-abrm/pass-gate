#pragma once

#include <cstdint>
#include <cstddef>

namespace GF256 {

    uint8_t add(uint8_t x, uint8_t y);
    uint8_t subtract(uint8_t x, uint8_t y);
    uint8_t multiply(uint8_t x, uint8_t y);
    uint8_t divide(uint8_t x, uint8_t y);

}
