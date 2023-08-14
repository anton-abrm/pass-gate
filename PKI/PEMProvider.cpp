#include "PEMProvider.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

void PKI::PEMProvider::initialize(std::string_view provider)
{
    std::unique_ptr<FILE, decltype(&fclose)> file(
            fopen(std::string(provider).c_str(), "r"),
            &fclose);

    if (!file)
        throw std::runtime_error("Unable to open file");

    EVP_PKEY * private_key = PEM_read_PrivateKey(file.get(), nullptr, password_callback, nullptr);

    if (!private_key)
        throw std::runtime_error("Unable to read private key");

    m_private_key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(private_key, &EVP_PKEY_free);

    m_initialized = true;
}

std::shared_ptr<PKI::PEMProvider> PKI::PEMProvider::instance() {

    static std::shared_ptr<PKI::PEMProvider> instance { new PKI::PEMProvider() };

    return instance;
}

int PKI::PEMProvider::password_callback(char *buffer, int size, int rwflag, void *u)
{
    std::string pass;

    if (!instance()->m_pin_callback ||
        !instance()->m_pin_callback(pass))
        return -1;

    if (size < pass.size())
        throw std::logic_error("Password too long");

    pass.copy(buffer, pass.size());

    return static_cast<int>(pass.size());
}

PKI::PEMProvider::PEMProvider() = default;

