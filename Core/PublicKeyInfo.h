#pragma once

#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <span>

namespace Core {

class PublicKeyInfo final {
public:

    static constexpr std::uint8_t public_key_token_size = 16;

    [[nodiscard]] std::string common_name() const;
    [[nodiscard]] std::vector<uint8_t> id() const;
    [[nodiscard]] std::array<uint8_t, public_key_token_size> public_key_token() const;

    void set_common_name(std::string_view value);
    void set_id(std::span<const uint8_t> value);
    void set_public_key_token(const std::array<uint8_t, public_key_token_size> &value);

private:
    std::string m_common_name;
    std::vector<uint8_t> m_id;
    std::array<uint8_t, public_key_token_size> m_public_key_token {};
};

}
