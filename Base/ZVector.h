#pragma once

#include <vector>

#include "ZAllocator.h"

namespace Base {
    template<typename T>
    using ZVector = std::vector<T, ZAllocator<T>>;
    using ZBytes = ZVector<uint8_t>;
}