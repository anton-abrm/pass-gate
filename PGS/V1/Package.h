#pragma once

#include <optional>
#include <memory>
#include <vector>
#include <string_view>
#include <span>

#include "PGS/V1/EntropySourceInfo.h"
#include "PGS/V1/EncryptionInfo.h"

namespace PGS::V1 {

    class Package final {

    public:
        static std::optional<std::unique_ptr<Package>> parse(std::string_view value);

        [[nodiscard]] std::string to_string() const;

        void set_entropy_source(std::shared_ptr<EntropySourceInfo> info);
        void set_encryption(std::shared_ptr<EncryptionInfo> encryption);
        void set_body(std::span<const uint8_t> body);

        [[nodiscard]] std::shared_ptr<EntropySourceInfo> entropy_source();
        [[nodiscard]] std::shared_ptr<EncryptionInfo> encryption();
        [[nodiscard]] std::vector<uint8_t> body() const;

    private:
        std::vector<uint8_t> m_body;
        std::shared_ptr<EntropySourceInfo> m_entropy_source;
        std::shared_ptr<EncryptionInfo> m_encryption;
    };
}
