#pragma once

#include <string_view>
#include <functional>
#include <optional>

#include "Base/ZString.h"

namespace Password {
    Base::ZString generate(std::string_view format, const std::function<int16_t()>& rng);
    std::optional<size_t> calculate_entropy(std::string_view format);
}
