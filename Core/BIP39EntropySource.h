#pragma once

#include "EntropySource.h"
#include "Base/ZString.h"

namespace Core
{

    class BIP39EntropySource: public virtual EntropySource
    {
    public:
        explicit BIP39EntropySource(std::string_view mnemonic);

        [[nodiscard]] Base::ZBytes get_seed(std::string_view nonce, std::size_t size) override;
        [[nodiscard]] std::size_t max_seed_size() const override;

    private:
        const Base::ZString m_mnemonic;
    };
}
