#pragma once

#include <string_view>

#include "PGS/Constants.h"
#include "PGS/V1/EntropySourceInfo.h"

namespace PGS::V1 {

    class EncryptionInfo final {
    public:

        constexpr static const std::string_view prefix = "enc";

        [[nodiscard]] static std::optional<std::unique_ptr<EncryptionInfo>> parse(std::string_view s);

        explicit EncryptionInfo(EncryptionVersion version);

        [[nodiscard]] std::string to_string() const;

        [[nodiscard]] EncryptionVersion version() const;

    private:
        EncryptionVersion m_version;
    };
}
