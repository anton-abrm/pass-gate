#include "Password.h"

#include <algorithm>
#include <vector>
#include <charconv>
#include <string_view>
#include <stdexcept>
#include <cmath>
#include <map>

static constexpr const char *c_alphabet_upper_all = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static constexpr const char *c_alphabet_upper_human = "ABCDEFGHJKLMNPQRSTUVWXYZ";
static constexpr const char *c_alphabet_lower_all = "abcdefghijklmnopqrstuvwxyz";
static constexpr const char *c_alphabet_lower_human = "abcdefghijkmnpqrstuvwxyz";
static constexpr const char *c_alphabet_digit_all = "0123456789";
static constexpr const char *c_alphabet_digit_human = "23456789";
static constexpr const char *c_alphabet_special_all = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
static constexpr const char *c_alphabet_special_human = "!#$%&()*+/<>?@[\\]^{}~";
static constexpr const char *c_alphabet_special_safe = "!#$%&*@^";
static constexpr const char *c_alphabet_hex = "0123456789abcdef";

static const std::string c_hhhs = std::string(c_alphabet_upper_human)
                                + std::string(c_alphabet_lower_human)
                                + std::string(c_alphabet_digit_human)
                                + std::string(c_alphabet_special_safe);

static std::map<char, uint8_t> generate_hhhs_lookup() {

    std::map<char, uint8_t> result;

    for (std::size_t i = 0; i < c_hhhs.length(); ++i) {
        result[c_hhhs[i]] = static_cast<uint8_t>(i);
    }

    return result;
}

static std::map<char, uint8_t> c_hhhs_lookup = generate_hhhs_lookup();

enum class PasswordType {
    Chars,
    Hex,
    Digits
};

static uint8_t next_byte(const std::function<int16_t()> &rng) {

    while (true) {
        const auto read = rng();
        if (read < 0) {
            throw std::runtime_error("Not enough entropy");
        }

        return static_cast<uint8_t>(read);
    }
}

static uint8_t next_byte(const std::function<int16_t()> &rng, const uint8_t max_excluded) {

    const uint8_t bound_excluded =
            std::numeric_limits<uint8_t>::max() - std::numeric_limits<uint8_t>::max() % max_excluded;

    while (true) {

        const auto current = next_byte(rng);

        if (current < bound_excluded) {
            return current % max_excluded;
        }
    }
}

static void shuffle(Base::ZString &password, const std::function<int16_t()> &rng) {
    for (Base::ZString::size_type i = 0; i < password.size(); i++) {
        const auto r = i + next_byte(rng, static_cast<uint8_t>(password.size() - i));     // between i and n-1
        const auto tmp = password[i];
        password[i] = password[r];
        password[r] = tmp;
    }
}

static std::optional<std::string_view>get_alphabet(const uint8_t position, const char ch) {

    if (position == 0) {

        switch (ch) {
            case 'a':
                return c_alphabet_upper_all;
            case 'h':
                return c_alphabet_upper_human;
            case 'x':
                return std::string_view();
            default:
                return std::nullopt;
        }
    }

    if (position == 1) {

        switch (ch) {
            case 'a':
                return c_alphabet_lower_all;
            case 'h':
                return c_alphabet_lower_human;
            case 'x':
                return std::string_view();
            default:
                return std::nullopt;
        }
    }

    if (position == 2) {

        switch (ch) {
            case 'a':
                return c_alphabet_digit_all;
            case 'h':
                return c_alphabet_digit_human;
            case 'x':
                return std::string_view();
            default:
                return std::nullopt;
        }
    }

    if (position == 3) {

        switch (ch) {
            case 'a':
                return c_alphabet_special_all;
            case 'h':
                return c_alphabet_special_human;
            case 's':
                return c_alphabet_special_safe;
            case 'x':
                return std::string_view();
            default:
                return std::nullopt;
        }
    }

    return nullptr;
}

static std::optional<std::vector<std::string_view>> parse_params(const std::string_view &format, uint8_t &password_length, PasswordType &password_type) {

    constexpr size_t c_max_alphabets = 4;

    if (format.size() < 5 || format.size() > 6)
        return std::nullopt;

    const std::size_t length_part_size = format.size() - c_max_alphabets;

    const std::string_view length_part(format.data(), length_part_size);
    const std::string_view format_part(format.data() + length_part_size, c_max_alphabets);

    const auto conversion_result = std::from_chars(
            length_part.data(),
            length_part.data() + length_part.size(),
            password_length);

    if (conversion_result.ec == std::errc::invalid_argument)
        return std::nullopt;

    std::vector<std::string_view> alphabets;

    alphabets.reserve(c_max_alphabets);

    if (format_part == "_hex") {
        alphabets.emplace_back(c_alphabet_hex);
        password_type = PasswordType::Hex;
        return alphabets;
    }

    if (format_part == "_dig") {
        alphabets.emplace_back(c_alphabet_digit_all);
        password_type = PasswordType::Digits;
        return alphabets;
    }

    for (size_t i = 0; i < format_part.size(); i++) {
        const auto alphabet = get_alphabet(static_cast<uint8_t>(i), format_part[i]);
        if (!alphabet)
            return std::nullopt;

        if (!alphabet.value().empty())
            alphabets.emplace_back(alphabet.value());
    }

    if (password_length < alphabets.size())
        return std::nullopt;

    password_type = PasswordType::Chars;

    return alphabets;
}

static std::string merge_alphabets(const std::vector<std::string_view> &alphabets) {

    std::string merged_alphabet;

    size_t merged_alphabet_size{0};

    for (const auto &alphabet: alphabets)
        merged_alphabet_size += alphabet.size();

    merged_alphabet.reserve(merged_alphabet_size);

    for (const auto &alphabet: alphabets)
        merged_alphabet.append(alphabet);

    return merged_alphabet;
}

namespace Password {

    Base::ZString generate(std::string_view format, const std::function<int16_t()> &rng) {

        uint8_t password_length{0};
        PasswordType password_type {0};

        const auto alphabets = parse_params(format, password_length, password_type);

        if (!alphabets)
            throw std::runtime_error("Invalid password format.");

        Base::ZString password;

        password.reserve(password_length);

        const std::string merged_alphabet = merge_alphabets(alphabets.value());

        if (password_type == PasswordType::Hex) {

            if (password_length % 2 != 0)
                throw std::runtime_error("The password length must be even.");

            while (password.size() < password_length) {
                const auto readByte = next_byte(rng);

                password.push_back(merged_alphabet[readByte >> 4]);
                password.push_back(merged_alphabet[readByte & 0xF]);
            }

            return password;
        }

        if (password_type == PasswordType::Digits)
        {
            while (password.size() < password_length)
            {
                const auto read_byte = next_byte(rng);

                const auto hi = read_byte >> 4;
                const auto lo = read_byte & 0xF;

                if (hi < merged_alphabet.length())
                    password.push_back(merged_alphabet[hi]);

                if (lo < merged_alphabet.length())
                    password.push_back(merged_alphabet[lo]);
            }

            password.resize(password_length);

            return password;
        }

        for (const auto &alphabet: alphabets.value())
            password.push_back(alphabet[next_byte(rng, static_cast<uint8_t>(alphabet.size()))]);

        while (password.size() < password_length)
            password.push_back(merged_alphabet[next_byte(rng, static_cast<uint8_t>(merged_alphabet.size()))]);

        shuffle(password, rng);

        return password;
    }

    std::optional<size_t> calculate_entropy(std::string_view format)
    {
        uint8_t password_length{0};
        PasswordType password_type {0};

        const auto alphabets = parse_params(format, password_length, password_type);

        if (!alphabets)
            return std::nullopt;

        const std::string merged_alphabet = merge_alphabets(alphabets.value());

        if (merged_alphabet.empty())
            return std::nullopt;

        return static_cast<size_t>(std::round(1.442695 * std::log(
                std::pow(static_cast<double>(merged_alphabet.size()), password_length))));
    }

    bool is_hhhs(std::string_view s) {
        return std::all_of(s.cbegin(), s.cend(), [](const auto c) {
            return c_hhhs_lookup.contains(c);
        });
    }

    Base::ZString encode_hhhs(std::span<const uint8_t> bytes) {

        Base::ZString output;

        output.reserve(
                bytes.size() / 3 * 4 +
                bytes.size() % 3 + 1);

        std::span<uint8_t>::size_type i = 0;

        for (; i < bytes.size() / 3 * 3; i += 3) {
            output.push_back(c_hhhs[(bytes[i]) >> 2]);
            output.push_back(c_hhhs[(bytes[i] & 0x03) << 4 | bytes[i + 1] >> 4]);
            output.push_back(c_hhhs[(bytes[i + 1] & 0x0F) << 2 | bytes[i + 2] >> 6]);
            output.push_back(c_hhhs[(bytes[i + 2] & 0x3F)]);
        }

        if (bytes.size() % 3 == 2) {
            output.push_back(c_hhhs[(bytes[i]) >> 2]);
            output.push_back(c_hhhs[(bytes[i] & 0x03) << 4 | bytes[i + 1] >> 4]);
            output.push_back(c_hhhs[(bytes[i + 1] & 0x0F) << 2]);
            return output;
        }

        if (bytes.size() % 3 == 1) {
            output.push_back(c_hhhs[(bytes[i]) >> 2]);
            output.push_back(c_hhhs[(bytes[i] & 0x03) << 4]);
            return output;
        }

        return output;
    }

    std::optional<Base::ZBytes> decode_hhhs(std::string_view s) {

        if (s.empty())
            return {};

        if (s.size() % 4 == 1 || !is_hhhs(s))
            return std::nullopt;

        Base::ZBytes::size_type output_size =
                s.size() / 4 * 3 +
                s.size() % 4 - 1;

        Base::ZBytes output;

        output.reserve(output_size);

        std::string_view::size_type i = 0;

        for (; i < s.size() / 4 * 4; i += 4) {
            output.push_back(c_hhhs_lookup.at(s[i]) << 2 | c_hhhs_lookup.at(s[i + 1]) >> 4);
            output.push_back(c_hhhs_lookup.at(s[i + 1]) << 4 | c_hhhs_lookup.at(s[i + 2]) >> 2);
            output.push_back(c_hhhs_lookup.at(s[i + 2]) << 6 | c_hhhs_lookup.at(s[i + 3]));
        }

        if (s.size() % 4 == 3) {
            output.push_back(c_hhhs_lookup.at(s[i]) << 2 | c_hhhs_lookup.at(s[i + 1]) >> 4);
            output.push_back(c_hhhs_lookup.at(s[i + 1]) << 4 | c_hhhs_lookup.at(s[i + 2]) >> 2);
            return output;
        }

        if (s.size() % 4 == 2) {
            output.push_back(c_hhhs_lookup.at(s[i]) << 2 | c_hhhs_lookup.at(s[i + 1]) >> 4);
            return output;
        }

        return output;
    }
}
