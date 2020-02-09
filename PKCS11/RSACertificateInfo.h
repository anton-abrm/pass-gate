#pragma once

#include <vector>
#include <string>

namespace PKCS11 {

class RSACertificateInfo final {
public:

    [[nodiscard]]
    const std::u8string &common_name() const { return m_common_name; }

    void set_common_name(const std::u8string_view &value) { m_common_name = value; }

    [[nodiscard]]
    const std::vector<uint8_t> &id() const { return m_id; }

    void set_id(const std::span<const uint8_t> &value) { m_id.assign(value.begin(), value.end()); }

    [[nodiscard]]
    const std::vector<uint8_t> &rsa_modulus() const { return m_rsa_modulus; }

    void set_rsa_modulus(const std::span<const uint8_t> &value) { m_rsa_modulus.assign(value.begin(), value.end()); }

private:
    std::u8string m_common_name;
    std::vector<uint8_t> m_id;
    std::vector<uint8_t> m_rsa_modulus;
};

}
