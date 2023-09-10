#pragma once

#include "PKIProvider.h"
#include "EntropySource.h"

namespace Core {

class SignatureEntropySourceV2 final : public virtual Core::EntropySource
{
public:

    explicit SignatureEntropySourceV2(
            const std::shared_ptr<const Core::PKIProvider> &provider,
            std::span<const uint8_t> id,
            std::string_view info);

    [[nodiscard]] Base::ZBytes get_seed(std::string_view nonce, std::size_t size) override;
    [[nodiscard]] std::size_t max_seed_size() const override;

private:
    const std::shared_ptr<const Core::PKIProvider> m_provider;
    std::vector<uint8_t> m_id;
    std::string m_info;
};

}
