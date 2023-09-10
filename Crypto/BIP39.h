#pragma once

#include <cstdint>
#include <string_view>
#include <vector>
#include <span>
#include <optional>

#include "Base/ZVector.h"
#include "Base/ZString.h"
#include "Crypto/Crypto.h"

namespace BIP39 {

    const size_t seed_size {64};

    std::optional<Base::ZBytes> mnemonic_to_seed(std::string_view mnemonic, std::string_view passphrase);
    std::optional<Base::ZString> entropy_to_mnemonic(std::span<const uint8_t> entropy);
    std::optional<Base::ZBytes> mnemonic_to_entropy(std::string_view);
}
