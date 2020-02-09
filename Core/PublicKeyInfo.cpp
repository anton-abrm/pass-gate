#include "PublicKeyInfo.h"

std::string Core::PublicKeyInfo::common_name() const
{
    return m_common_name;
}

std::vector<uint8_t> Core::PublicKeyInfo::id() const
{
    return m_id;
}

std::array<uint8_t, Core::PublicKeyInfo::public_key_token_size> Core::PublicKeyInfo::public_key_token() const
{
    return m_public_key_token;
}

void Core::PublicKeyInfo::set_common_name(std::string_view value)
{
    m_common_name = value;
}

void Core::PublicKeyInfo::set_id(std::span<const uint8_t> value)
{
    m_id.assign(value.begin(), value.end());
}

void Core::PublicKeyInfo::set_public_key_token(const std::array<uint8_t, Core::PublicKeyInfo::public_key_token_size> &value)
{
    m_public_key_token = value;
}


