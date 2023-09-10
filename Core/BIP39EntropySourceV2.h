#pragma once

#include "EntropySource.h"
#include "Base/ZString.h"

namespace Core
{

    class BIP39EntropySourceV2: public virtual EntropySource
    {
    public:
        explicit BIP39EntropySourceV2(std::string_view mnemonic, std::string_view info);

        [[nodiscard]] Base::ZBytes get_seed(std::string_view nonce, std::size_t size) override;
        [[nodiscard]] std::size_t max_seed_size() const override;

    private:
        const Base::ZString m_mnemonic;
        const std::string m_info;
    };
}
