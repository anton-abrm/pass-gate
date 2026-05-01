#pragma once

#include "Base/ZString.h"
#include "Base/ZVector.h"
#include "Core/EntropySource.h"
#include "PKIProvider.h"
#include <cstdint>
#include <span>
#include <string>

namespace Core {

    class AadEncryptionService {

    public:
        [[nodiscard]] virtual Base::ZBytes encrypt(std::string_view plain, std::string_view aad) const = 0;
        [[nodiscard]] virtual Base::ZString decrypt(std::span<const uint8_t> body, std::string_view aad) const = 0;

        virtual ~AadEncryptionService();
    };

} // Core
