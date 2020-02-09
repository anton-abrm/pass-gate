#pragma once

#include "Base/ZString.h"
#include "Base/ZVector.h"
#include "Core/EntropySource.h"
#include "PKIProvider.h"
#include <cstdint>
#include <span>
#include <string>

namespace Core {

    class EncryptionService {

    public:
        [[nodiscard]] virtual Base::ZBytes encrypt(std::string_view plain) const = 0;
        [[nodiscard]] virtual Base::ZString decrypt(std::span<const uint8_t> body) const = 0;

        virtual ~EncryptionService();
    };

} // Core
