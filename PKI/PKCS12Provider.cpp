#include "PKCS12Provider.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

void PKI::PKCS12Provider::initialize(std::string_view provider)
{
    std::unique_ptr<FILE, decltype(&fclose)> file(
            fopen(std::string(provider).c_str(), "r"),
            &fclose);

    if (!file)
        throw std::runtime_error("Unable to open file");

    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> p12(
            d2i_PKCS12_fp(file.get(), nullptr),
            &PKCS12_free);

    if (!p12)
        throw std::runtime_error("Unable to parse PKCS12 file");

    std::string pass;

    if (1 != PKCS12_verify_mac(p12.get(), "", 0))
    {
        if (!m_pin_callback || !m_pin_callback(pass))
            throw std::runtime_error("Password is required.");
    }

    EVP_PKEY * pkey = nullptr;
    X509 * cert = nullptr;

    if (1 != PKCS12_parse(p12.get(), pass.c_str(), &pkey, &cert, nullptr))
        throw std::runtime_error("Unable to parse PKCS12 file");

    m_private_key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(pkey, &EVP_PKEY_free);
    m_x509_certificate = std::unique_ptr<X509, decltype(&X509_free)>(cert, &X509_free);

    m_initialized = true;
}

std::shared_ptr<PKI::PKCS12Provider> PKI::PKCS12Provider::instance() {
    
    static std::shared_ptr<PKI::PKCS12Provider> instance { new PKI::PKCS12Provider() };

    return instance;
}

PKI::PKCS12Provider::PKCS12Provider() = default;

