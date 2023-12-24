#pragma once

#include <string_view>

#include "PGS/Constants.h"
#include "PGS/V1/EntropySourceInfo.h"

namespace PGS::V1 {

    class RandomEntropySource final : public virtual EntropySourceInfo {
    public:

        constexpr static const std::string_view prefix = "rand";

        [[nodiscard]] static std::optional<std::unique_ptr<RandomEntropySource>> parse(std::string_view s);

        [[nodiscard]] EntropySourceType type() const override;
        [[nodiscard]] std::string to_string() const override;
    };
}
