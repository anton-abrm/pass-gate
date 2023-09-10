#pragma once

#include <string>
#include <span>

#include "Base/ZString.h"
#include "Base/ZVector.h"

namespace Base {

    class Encoding {
    public:
        static Base::ZString encode_base64_url_no_padding(std::span<const uint8_t> bytes);
        static Base::ZBytes decode_base64_any(std::string_view s);
        static Base::ZString encode_hex_lower(std::span<const uint8_t> bytes);
        static Base::ZBytes decode_hex_any(std::string_view s);

    };
}