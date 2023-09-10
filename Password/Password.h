#pragma once

#include <string_view>
#include <functional>
#include <optional>
#include <span>

#include "Base/ZString.h"
#include "Base/ZVector.h"

namespace Password {
    Base::ZString generate(std::string_view format, const std::function<int16_t()>& rng);
    std::optional<size_t> calculate_entropy(std::string_view format);
    bool is_hhhs(std::string_view s);
    Base::ZString encode_hhhs(std::span<const uint8_t> bytes);
    std::optional<Base::ZBytes> decode_hhhs(std::string_view s);
}
