#pragma once

#include <string>

#include "ZAllocator.h"

namespace Base {
    template<typename T>
    using ZBasicString = std::basic_string<T, std::char_traits<T>, ZAllocator<T>>;
    using ZString = ZBasicString<char>;
}