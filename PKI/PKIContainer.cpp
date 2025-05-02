#include "PKIContainer.h"

#include <algorithm>

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "Base/Encoding.h"

static std::vector<uint8_t> get_rsa_modulus(EVP_PKEY &pkey) {

    std::unique_ptr<RSA, decltype(&RSA_free)> rsa(
            EVP_PKEY_get1_RSA(&pkey),
            &RSA_free);

    const BIGNUM *n = RSA_get0_n(rsa.get());

    std::vector<uint8_t> result(BN_num_bytes(n));

    BN_bn2bin(n, result.data());

    return result;
}

static std::string_view x509_get_common_name(X509 &x509) {

    X509_NAME *subject = X509_get_subject_name(&x509);

    for (int i = 0; i < X509_NAME_entry_count(subject); i++) {

        X509_NAME_ENTRY *nameEntry = X509_NAME_get_entry(subject, i);
        ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(nameEntry);

        if (OBJ_obj2nid(obj) == NID_commonName) {

            ASN1_STRING *d = X509_NAME_ENTRY_get_data(nameEntry);

            return {
                    reinterpret_cast<const char *>(ASN1_STRING_get0_data(d)),
                    static_cast<std::string_view::size_type>(ASN1_STRING_length(d))
            };
        }
    }

    return {};
}

void PKI::PKIContainer::terminate()
{
    m_private_key = nullptr;
    m_x509_certificate = nullptr;
    m_initialized = false;
}

std::vector<Core::PublicKeyInfo> PKI::PKIContainer::get_certificates() const
{
    auto cert_infos = std::vector<Core::PublicKeyInfo>();

    if (m_private_key)
    {
        auto rsa_modulus = get_rsa_modulus(*m_private_key);

        std::string common_name;

        if (m_x509_certificate) {
            common_name = x509_get_common_name(*m_x509_certificate);
        }
        else {
            common_name.append("rsa-");
            common_name.append(std::to_string(rsa_modulus.size() * 8));
            common_name.append("-");
            common_name.append(Base::Encoding::encode_hex_lower({rsa_modulus.data(), 4}));
        }

        std::array<uint8_t, Core::PublicKeyInfo::public_key_token_size> public_key_token {0};

        std::copy_n(
                rsa_modulus.begin(),
                public_key_token.size(),
                public_key_token.begin());

        Core::PublicKeyInfo cert_info;

        cert_info.set_common_name(common_name);
        cert_info.set_public_key_token(public_key_token);
        cert_info.set_id({rsa_modulus.data(), 8});

        cert_infos.push_back(std::move(cert_info));
    }

    return cert_infos;
}

Base::ZBytes PKI::PKIContainer::sign(std::span<const uint8_t> id, std::span<const uint8_t> data) const
{
    if (!m_private_key)
        throw std::runtime_error("Key is not initialized.");

    auto modulus = get_rsa_modulus(*m_private_key);

    if (!std::equal(id.begin(), id.end(), modulus.begin()))
        throw std::runtime_error("Key with specified token not found.");

    std::unique_ptr<EVP_PKEY_CTX , decltype(&EVP_PKEY_CTX_free)> ctx(
            EVP_PKEY_CTX_new(m_private_key.get(), nullptr /* no engine */),
            &EVP_PKEY_CTX_free);

    if (!ctx)
        throw std::runtime_error("Unable to create signing context.");

    if (EVP_PKEY_sign_init(ctx.get()) <= 0)
        throw std::runtime_error("Unable to initialize signing context.");

    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) <= 0)
        throw std::runtime_error("Unable to set RSA padding.");

    if (EVP_PKEY_CTX_set_signature_md(ctx.get(), EVP_sha512()) <= 0)
        throw std::runtime_error("Unable to set SHA 512 digest.");

    size_t sign_length = 0;

    unsigned char md[SHA512_DIGEST_LENGTH]{0};

    SHA512(data.data(), data.size(), md);

    if (EVP_PKEY_sign(ctx.get(), nullptr, &sign_length, md, sizeof(md)) <= 0)
        throw std::runtime_error("Unable to determine sign length.");

    Base::ZBytes sign(sign_length);

    if (EVP_PKEY_sign(ctx.get(), sign.data(), &sign_length, md, sizeof(md)) <= 0)
        throw std::runtime_error("Unable to sign data.");

    return sign;
}

void PKI::PKIContainer::set_pin_callback(std::function<bool(std::string &)> callback)
{
    m_pin_callback = std::move(callback);
}

bool PKI::PKIContainer::is_initialized() const {
    return m_initialized;
}
