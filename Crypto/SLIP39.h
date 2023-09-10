#pragma once

#include <span>
#include <string_view>

#include "Base/ZVector.h"

namespace SLIP39 {

    Base::ZBytes encrypt_master_secret(std::span<const uint8_t> plain, uint8_t e, uint16_t id, std::string_view passphrase);
    Base::ZBytes decrypt_master_secret(std::span<const uint8_t> cipher, uint8_t e, uint16_t id, std::string_view passphrase);

}
