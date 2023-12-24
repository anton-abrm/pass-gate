#pragma once

#include <string_view>

#include "PGS/Constants.h"
#include "PGS/V1/EntropySourceInfo.h"

namespace PGS::V1 {

    class SignatureEntropySourceInfo final : public virtual EntropySourceInfo {
    public:

        static constexpr const std::string_view prefix = "sign";

        [[nodiscard]] static std::optional<std::unique_ptr<SignatureEntropySourceInfo>> parse(std::string_view s);

        explicit SignatureEntropySourceInfo(PGS::SignatureVersion version);

        [[nodiscard]] EntropySourceType type() const override;
        [[nodiscard]] std::string to_string() const override;

        [[nodiscard]] SignatureVersion version() const;

    private:
        SignatureVersion m_version;
    };
}
