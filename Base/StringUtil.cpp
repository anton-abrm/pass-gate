#include "StringUtil.h"

std::vector<std::string_view> Base::StringUtil::split(std::string_view s, const char delimiter) {

    size_t start = 0;

    std::vector<std::string_view> v;

    while (true)
    {
        size_t end = s.find(delimiter, start);

        if (end == std::string_view::npos)
            break;

        v.emplace_back(s.substr(start, end - start));

        start = end + 1;
    }

    v.emplace_back(s.substr(start, s.size() - start));

    return v;
}