#include "RSACertificate.h"

#include <pkcs11-helper-1.0/pkcs11h-certificate.h>

#include <openssl/x509.h>
#include <openssl/asn1.h>

#include "Exception.h"

static constexpr size_t c_max_signature_size = 4096;
static constexpr size_t c_max_certificate_size = 4096;

static std::vector<uint8_t> x509_get_rsa_modulus(X509 &x509) {

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> evp_pkey(
            X509_get_pubkey(&x509),
    &EVP_PKEY_free);

    std::unique_ptr<RSA, decltype(&RSA_free)> rsa(
            EVP_PKEY_get1_RSA(evp_pkey.get()),
            &RSA_free);

    const BIGNUM *n = RSA_get0_n(rsa.get());

    std::vector<uint8_t> result(BN_num_bytes(n));

    BN_bn2bin(n, result.data());

    return result;
}

static std::u8string_view x509_get_common_name(X509 &x509) {

    X509_NAME *subject = X509_get_subject_name(&x509);

    for (int i = 0; i < X509_NAME_entry_count(subject); i++) {

        X509_NAME_ENTRY *nameEntry = X509_NAME_get_entry(subject, i);
        ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(nameEntry);

        if (OBJ_obj2nid(obj) == NID_commonName) {

            ASN1_STRING *d = X509_NAME_ENTRY_get_data(nameEntry);

            return reinterpret_cast<const char8_t *>(
                    ASN1_STRING_get0_data(d));
        }
    }

    return {};
}

static void check_ck_rv(const char *message, CK_RV rv) {
    if (rv != CKR_OK)
        throw PKCS11::Exception(
                std::string(message) +
                std::string(" ") +
                std::string(pkcs11h_getMessage(rv)));
}

namespace PKCS11 {

    RSACertificate::~RSACertificate() {
        pkcs11h_certificate_freeCertificate(
                reinterpret_cast<pkcs11h_certificate_t>(m_certificate));
    }

    RSACertificate::RSACertificate(void *certificate)
            : m_certificate(certificate) {
    }

    std::unique_ptr<RSACertificate> RSACertificate::get_certificate(const std::span<const uint8_t> &id) {

        pkcs11h_certificate_id_list_t cert_ids{nullptr};

        std::unique_ptr<pkcs11h_certificate_id_list_s, decltype(&pkcs11h_certificate_freeCertificateIdList)>
                certificates_guard(cert_ids, &pkcs11h_certificate_freeCertificateIdList);

        check_ck_rv("Unable to get cert_ids.",
                    pkcs11h_certificate_enumCertificateIds(
                            PKCS11H_ENUM_METHOD_CACHE,
                            nullptr,
                            PKCS11H_PROMPT_MASK_ALLOW_ALL,
                            nullptr,
                            &cert_ids));

        pkcs11h_certificate_t result{nullptr};

        for (auto cert_id = cert_ids; cert_id != nullptr; cert_id = cert_id->next) {

            const std::span<const uint8_t> current_id(
                    cert_id->certificate_id->attrCKA_ID,
                    cert_id->certificate_id->attrCKA_ID_size);

            if (id.size() != current_id.size())
                continue;

            if (!std::equal(id.begin(), id.end(), current_id.begin()))
                continue;

            check_ck_rv("Unable to create certificate.",
                        pkcs11h_certificate_create(
                                cert_id->certificate_id,
                                nullptr,
                                PKCS11H_PROMPT_MASK_ALLOW_ALL,
                                PKCS11H_PIN_CACHE_INFINITE,
                                &result));
            break;
        }

        return std::unique_ptr<RSACertificate>(new RSACertificate(result));
    }

    std::vector<uint8_t> RSACertificate::encrypt(const std::span<const uint8_t> &data) const {

        size_t cert_size{c_max_certificate_size};

        auto certificate_blob{std::make_unique<uint8_t[]>(cert_size)};

        check_ck_rv("Unable to get certificate_blob.",
                    pkcs11h_certificate_getCertificateBlob(
                            reinterpret_cast<pkcs11h_certificate_t>(m_certificate),
                            certificate_blob.get(),
                            &cert_size));

        std::unique_ptr<BIO, decltype(&BIO_free)> bio(
                BIO_new_mem_buf(
                        certificate_blob.get(),
                        static_cast<int>(cert_size)),
                &BIO_free);

        X509 *x509_ptr{nullptr};

        d2i_X509_bio(bio.get(), &x509_ptr);

        std::unique_ptr<X509, decltype(&X509_free)> x509(
                x509_ptr,
                &X509_free);

        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> evp_pkey(
                X509_get_pubkey(x509.get()),
                &EVP_PKEY_free);

        std::unique_ptr<RSA, decltype(&RSA_free)> rsa(
                EVP_PKEY_get1_RSA(evp_pkey.get()),
                &RSA_free);

        std::vector<uint8_t> cipher;

        cipher.resize(RSA_size(rsa.get()));

        auto cipher_size = RSA_public_encrypt(
                static_cast<int>(data.size()),
                data.data(),
                cipher.data(),
                rsa.get(),
                RSA_PKCS1_PADDING);

        if (cipher_size == -1)
            throw std::logic_error("Unable to encrypt data.");

        cipher.resize(cipher_size);

        return cipher;
    }

    std::vector<uint8_t> RSACertificate::decrypt(const std::span<const uint8_t> &data) const {

        size_t plain_size{c_max_signature_size};

        std::vector<uint8_t> plain(plain_size);

        check_ck_rv("Unable to decrypt data.",
                    pkcs11h_certificate_decrypt(
                            reinterpret_cast<pkcs11h_certificate_t>(m_certificate),
                            CKM_RSA_PKCS,
                            data.data(),
                            data.size(),
                            plain.data(),
                            &plain_size
                    ));

        plain.resize(plain_size);

        return plain;
    }

    std::vector<uint8_t> RSACertificate::sign(const std::span<const uint8_t> &data) const {

        size_t sign_size{c_max_signature_size};

        std::vector<uint8_t> sign_blob(sign_size);

        check_ck_rv("Unable to sign blob.",
                    pkcs11h_certificate_sign(
                            reinterpret_cast<pkcs11h_certificate_t>(m_certificate),
                            CKM_SHA512_RSA_PKCS,
                            data.data(),
                            data.size(),
                            sign_blob.data(),
                            &sign_size
                    ));

        sign_blob.resize(static_cast<int>(sign_size));

        return sign_blob;
    }

}
