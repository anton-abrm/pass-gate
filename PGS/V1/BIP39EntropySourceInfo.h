#pragma once

#include <string_view>

#include "PGS/Constants.h"
#include "PGS/V1/EntropySourceInfo.h"

namespace PGS::V1 {

    class BIP39EntropySourceInfo final : public virtual EntropySourceInfo {
    public:

        constexpr static const std::string_view prefix = "bip39";

        [[nodiscard]] static std::optional<std::unique_ptr<BIP39EntropySourceInfo>> parse(std::string_view s);

        explicit BIP39EntropySourceInfo(BIP39Version version);

        [[nodiscard]] EntropySourceType type() const override;
        [[nodiscard]] std::string to_string() const override;

        [[nodiscard]] BIP39Version version() const;

    private:
        BIP39Version m_version;
    };
}
