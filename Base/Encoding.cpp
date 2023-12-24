#include "Encoding.h"

const char * c_a64u =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_";

const char * c_a16 =
        "0123456789abcdef";

static thread_local bool tl_error;

Base::ZString Base::Encoding::encode_base64_url_no_padding(std::span<const uint8_t> bytes) {

    Base::ZString output;

    output.reserve(
            bytes.size() / 3 * 4 +
            bytes.size() % 3 + 1);

    std::span<uint8_t>::size_type i = 0;

    for (; i < bytes.size() / 3 * 3; i += 3) {
        output.push_back(c_a64u[(bytes[i]) >> 2]);
        output.push_back(c_a64u[(bytes[i] & 0x03) << 4 | bytes[i + 1] >> 4]);
        output.push_back(c_a64u[(bytes[i + 1] & 0x0F) << 2 | bytes[i + 2] >> 6]);
        output.push_back(c_a64u[(bytes[i + 2] & 0x3F)]);
    }

    if (bytes.size() % 3 == 2) {
        output.push_back(c_a64u[(bytes[i]) >> 2]);
        output.push_back(c_a64u[(bytes[i] & 0x03) << 4 | bytes[i + 1] >> 4]);
        output.push_back(c_a64u[(bytes[i + 1] & 0x0F) << 2]);
        return output;
    }

    if (bytes.size() % 3 == 1) {
        output.push_back(c_a64u[(bytes[i]) >> 2]);
        output.push_back(c_a64u[(bytes[i] & 0x03) << 4]);
        return output;
    }

    return output;
}

static uint8_t b64_idx(const char c) {

    if (c >= 'A' && c <= 'Z')
        return c - 'A';

    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;

    if (c >= '0' && c <= '9')
        return c - '0' + 26 + 26;

    if (c == '-' || c == '+')
        return 62;

    if (c == '_' || c == '/')
        return 63;

    tl_error = true;

    return 0;
}

std::optional<Base::ZBytes> Base::Encoding::decode_base64_any(std::string_view s)
{
    tl_error = false;

    Base::ZBytes output;

    if (s.empty())
        return output;

    if (s.ends_with('='))
        s.remove_suffix(1);

    if (s.ends_with('='))
        s.remove_suffix(1);

    if (s.size() % 4 == 1)
        return std::nullopt;

    Base::ZBytes::size_type output_size =
            s.size() / 4 * 3 +
            s.size() % 4 - 1;

    output.reserve(output_size);

    std::string_view::size_type i = 0;

    for (; i < s.size() / 4 * 4; i += 4) {

        output.push_back(b64_idx(s[i]) << 2 | b64_idx(s[i + 1]) >> 4);
        output.push_back(b64_idx(s[i + 1]) << 4 | b64_idx(s[i + 2]) >> 2);
        output.push_back(b64_idx(s[i + 2]) << 6 | b64_idx(s[i + 3]));

        if (tl_error)
            return std::nullopt;
    }

    if (s.size() % 4 == 3) {

        output.push_back(b64_idx(s[i]) << 2 | b64_idx(s[i + 1]) >> 4);
        output.push_back(b64_idx(s[i + 1]) << 4 | b64_idx(s[i + 2]) >> 2);

        if (tl_error)
            return std::nullopt;

        return output;
    }

    if (s.size() % 4 == 2) {

        output.push_back(b64_idx(s[i]) << 2 | b64_idx(s[i + 1]) >> 4);

        if (tl_error)
            return std::nullopt;

        return output;
    }

    return output;
}



Base::ZString Base::Encoding::encode_hex_lower(std::span<const uint8_t> bytes)
{
    Base::ZString result;

    result.reserve(bytes.size() * 2);

    for (const auto b : bytes)
    {
        result.push_back(c_a16[b >> 4]);
        result.push_back(c_a16[b & 0xF]);
    }

    return result;
}

static uint8_t b16_idx(const char c) {

    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    tl_error = true;

    return 0;
}

std::optional<Base::ZBytes> Base::Encoding::decode_hex_any(std::string_view s)
{
    tl_error = false;

    if (s.size() % 2 != 0)
        return std::nullopt;

    Base::ZBytes output;

    output.reserve(s.size() / 2);

    for (std::string_view::size_type i = 0; i < s.size(); i += 2)
    {
        output.push_back(b16_idx(s[i]) << 4 | b16_idx(s[i + 1]));

        if (tl_error)
            return std::nullopt;
    }

    return output;
}
