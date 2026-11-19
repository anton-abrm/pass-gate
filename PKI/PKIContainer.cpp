#include "PKIContainer.h"

#include <algorithm>

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>

#include "Base/Encoding.h"

static std::vector<uint8_t> get_rsa_modulus(const EVP_PKEY &pkey) {

    BIGNUM *n = nullptr;

    if (!EVP_PKEY_get_bn_param(&pkey, OSSL_PKEY_PARAM_RSA_N, &n)) {
        throw std::runtime_error("Unable to retrieve RSA modulus.");
    }

    std::unique_ptr<BIGNUM, decltype(&BN_free)> n_guard(n, &BN_free);

    std::vector<uint8_t> result(BN_num_bytes(n));

    BN_bn2bin(n, result.data());

    return result;
}

static std::string_view x509_get_common_name(const X509 &x509) {

    const X509_NAME *subject = X509_get_subject_name(&x509);

    for (int i = 0; i < X509_NAME_entry_count(subject); i++) {

        const X509_NAME_ENTRY *ne = X509_NAME_get_entry(subject, i);

        if (const ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(ne); OBJ_obj2nid(obj) == NID_commonName) {

            const ASN1_STRING *d = X509_NAME_ENTRY_get_data(ne);

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

    if (auto modulus = get_rsa_modulus(*m_private_key); !std::equal(id.begin(), id.end(), modulus.begin()))
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

    if (!SHA512(data.data(), data.size(), md))
        throw std::runtime_error("Unable to compute SHA 512.");

    if (EVP_PKEY_sign(ctx.get(), nullptr, &sign_length, md, sizeof(md)) <= 0)
        throw std::runtime_error("Unable to determine sign length.");

    Base::ZBytes sign(sign_length);

    if (EVP_PKEY_sign(ctx.get(), sign.data(), &sign_length, md, sizeof(md)) <= 0)
        throw std::runtime_error("Unable to sign data.");

    sign.resize(sign_length);

    return sign;
}

void PKI::PKIContainer::set_pin_callback(std::function<bool(std::string &)> callback)
{
    m_pin_callback = std::move(callback);
}

bool PKI::PKIContainer::is_initialized() const {
    return m_initialized;
}
