#pragma once

#include <string>
#include <span>
#include <cstdint>

#include "PKIProvider.h"
#include "Core/EntropySource.h"
#include "Base/ZVector.h"
#include "Base/ZString.h"
#include "Core/EncryptionService.h"

namespace Core {

class EncryptionServiceV1 final : public virtual Core::EncryptionService
    {
    public:

        explicit EncryptionServiceV1(
                std::shared_ptr<Core::EntropySource> entropy_source,
                std::shared_ptr<Core::RandomNumberGenerator> rng,
                std::string_view passphrase);

    [[nodiscard]] Base::ZBytes encrypt(std::string_view plain) const override;
    [[nodiscard]] Base::ZString decrypt(std::span<const uint8_t> body) const override;

    private:
        const std::shared_ptr<Core::EntropySource> m_entropy_source;
        const std::shared_ptr<Core::RandomNumberGenerator> m_rng;
        const std::string m_passphrase;
    };

}

