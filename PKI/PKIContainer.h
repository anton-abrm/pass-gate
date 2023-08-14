#pragma once

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "Core/PKIProvider.h"

namespace PKI
{

    class PKIContainer : public virtual Core::PKIProvider {

    public:

        Base::ZBytes sign(std::span<const uint8_t> id, std::span<const uint8_t> data) const override;

        Base::ZBytes generate_random(std::size_t length) const override;

        void terminate() override;

        std::vector<Core::PublicKeyInfo> get_certificates() const override;

        void set_pin_callback(std::function<bool(std::string &)> callback) override;

        void set_slot_callback(std::function<void()> callback) override;

        bool is_initialized() const override;

    protected:

        bool m_initialized{false};

        std::function<bool(std::string &)> m_pin_callback;

        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> m_private_key{
                std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(nullptr, &EVP_PKEY_free)};

        std::unique_ptr<X509, decltype(&X509_free)> m_x509_certificate{
                std::unique_ptr<X509, decltype(&X509_free)>(nullptr, &X509_free)};
    };
}
