#include "Password.h"

#include <vector>
#include <charconv>
#include <string_view>
#include <stdexcept>

static constexpr const char *c_alphabet_upper_all = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static constexpr const char *c_alphabet_upper_human = "ABCDEFGHJKLMNPQRSTUVWXYZ";
static constexpr const char *c_alphabet_lower_all = "abcdefghijklmnopqrstuvwxyz";
static constexpr const char *c_alphabet_lower_human = "abcdefghijkmnpqrstuvwxyz";
static constexpr const char *c_alphabet_digit_all = "0123456789";
static constexpr const char *c_alphabet_digit_human = "23456789";
static constexpr const char *c_alphabet_special_all = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
static constexpr const char *c_alphabet_special_human = "!#$%&()*+/<>?@[\\]^{}~";
static constexpr const char *c_alphabet_special_safe = "!#$%&*@^";

static uint8_t next_byte(const std::function<int16_t()> &rng, uint8_t max) {

    unsigned int bound = 256u - (256u % max);

    while (true) {
        int read = rng();
        if (read < 0) {
            throw std::runtime_error("Not enough entropy");
        }

        auto cur = (uint8_t) read;

        if (cur < bound) {
            return cur % max;
        }
    }
}

static void shuffle(std::string &password, const std::function<int16_t()> &rng) {
    for (size_t i = 0; i < password.size(); i++) {
        auto r = i + next_byte(rng, password.size() - i);     // between i and n-1
        auto tmp = password[i];
        password[i] = password[r];
        password[r] = tmp;
    }
}

static const char *get_alphabet(const uint8_t position, const char ch) {

    if (position == 0) {

        switch (ch) {
            case 'a':
                return c_alphabet_upper_all;
            case 'h':
                return c_alphabet_upper_human;
            case 'x':
                return nullptr;
            default:
                throw std::runtime_error("Invalid upper case specifier.");
        }
    }

    if (position == 1) {

        switch (ch) {
            case 'a':
                return c_alphabet_lower_all;
            case 'h':
                return c_alphabet_lower_human;
            case 'x':
                return nullptr;
            default:
                throw std::runtime_error("Invalid lower case specifier.");
        }
    }

    if (position == 2) {

        switch (ch) {
            case 'a':
                return c_alphabet_digit_all;
            case 'h':
                return c_alphabet_digit_human;
            case 'x':
                return nullptr;
            default:
                throw std::runtime_error("Invalid digit specifier.");
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
                return nullptr;
            default:
                throw std::runtime_error("Invalid special char specifier.");
        }
    }

    return nullptr;
}

static std::vector<std::string_view> parse_params(const std::string_view &format, uint8_t &password_length) {

    constexpr size_t c_max_alphabets = 4;

    if (format.size() < 5 || format.size() > 6)
        throw std::runtime_error("Invalid password format.");

    const std::string_view length_part(format.begin(), format.end() - c_max_alphabets);
    const std::string_view format_part(format.end() - c_max_alphabets, format.end());

    const auto conversion_result = std::from_chars(
            length_part.begin(), length_part.end(), password_length);

    if (conversion_result.ec == std::errc::invalid_argument)
        throw std::runtime_error("Invalid password length.");

    std::vector<std::string_view> alphabets;

    alphabets.reserve(c_max_alphabets);

    for (size_t i = 0; i < format_part.size(); i++) {
        const auto *alphabet = get_alphabet(i, format_part[i]);
        if (alphabet)
            alphabets.emplace_back(alphabet);
    }

    if (password_length < alphabets.size())
        throw std::runtime_error("Password can not be less than alphabets used.");

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

    std::string generate(const std::string_view &format, const std::function<int16_t()> &rng) {

        uint8_t password_length{0};

        const auto alphabets = parse_params(format, password_length);

        std::string password;

        password.reserve(password_length);

        for (const auto &alphabet: alphabets)
            password.push_back(alphabet[next_byte(rng, alphabet.size())]);

        const std::string merged_alphabet = merge_alphabets(alphabets);

        while (password.size() < password_length)
            password.push_back(merged_alphabet[next_byte(rng, merged_alphabet.size())]);

        shuffle(password, rng);

        return password;
    }
}