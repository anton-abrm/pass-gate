#pragma once

#include <stdexcept>

namespace PKCS11 {
    class Exception final : public std::runtime_error {
    public:
        explicit Exception(const std::string_view &message)
                : std::runtime_error(message.data()) {
        }
    };
}


