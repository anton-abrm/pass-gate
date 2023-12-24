#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <memory>

#include "PGS/Constants.h"

namespace PGS::V1 {

class EntropySourceInfo {
public:

    [[nodiscard]] static std::optional<std::unique_ptr<EntropySourceInfo>> parse(std::string_view s);

    [[nodiscard]] virtual EntropySourceType type() const = 0;
    [[nodiscard]] virtual std::string to_string() const = 0;

    [[nodiscard]] std::string token() const;

    void set_token(std::string_view token);

    virtual ~EntropySourceInfo();

private:
    std::string m_token;
};

}
