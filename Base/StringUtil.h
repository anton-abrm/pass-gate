#pragma once

#include <vector>
#include <string_view>

namespace Base {

    class StringUtil {
    public:
        [[nodiscard]] static std::vector<std::string_view> split(std::string_view s, char delimiter);
    };
}