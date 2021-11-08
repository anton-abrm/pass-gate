#pragma once

#include <span>
#include <memory>
#include <vector>

namespace PKCS11 {

    class RSACertificate final {

    private:
        explicit RSACertificate(void *certificate);

    public:
        [[nodiscard]] std::vector<uint8_t> encrypt(const std::span<const uint8_t> &data) const;
        [[nodiscard]] std::vector<uint8_t> decrypt(const std::span<const uint8_t> &data) const;
        [[nodiscard]] std::vector<uint8_t> sign(const std::span<const uint8_t> &data) const;

        virtual ~RSACertificate();

        static std::unique_ptr<RSACertificate> get_certificate(const std::span<const uint8_t> &id);

    private:
        void *m_certificate;
    };
}



