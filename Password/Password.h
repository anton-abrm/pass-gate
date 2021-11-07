#pragma once

#include <string_view>
#include <functional>

namespace Password {
    std::string generate(const std::string_view &format, const std::function<int16_t()>& rng);
}
