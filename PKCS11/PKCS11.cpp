#include "PKCS11.h"
#include "Exception.h"

#include <memory>

#include <openssl/x509.h>
#include <openssl/asn1.h>

#include <pkcs11-helper-1.0/pkcs11h-certificate.h>

static constexpr size_t c_max_certificate_size = 4096;

static std::function<bool(std::u8string &)> pin_callback;
static std::function<void()> slot_callback;

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

static PKCS11H_BOOL pkcs11h_token_prompt(
        IN  [[maybe_unused]] void *const global_data,
        IN  [[maybe_unused]] void *const user_data,
        IN  [[maybe_unused]] pkcs11h_token_id_t token,
        IN  [[maybe_unused]] const unsigned retry
) {
    throw std::logic_error("Token not inserted");
}

static void pkcs11h_slot_event(
        IN  [[maybe_unused]] void *const global_data
) {
    if (slot_callback)
        slot_callback();
}

static PKCS11H_BOOL pkcs11h_pin_prompt(
        IN [[maybe_unused]] void *const global_data,
        IN [[maybe_unused]] void *const user_data,
        IN [[maybe_unused]] pkcs11h_token_id_t token,
        IN [[maybe_unused]] const unsigned retry,
        OUT char *const pin,
        IN const size_t pin_max
) {

    if (!pin_callback)
        return false;

    std::u8string pass;

    if (!pin_callback(pass))
        return false;

    if (pin_max < pass.size())
        throw std::logic_error("Password too long");

    pass.copy(reinterpret_cast<char8_t *>(pin), pass.size());

    pin[pass.size()] = '\0';

    return true;
}

namespace PKCS11 {

    void initialize() {

        check_ck_rv("Unable to initialize PKCS11 library.",
                    pkcs11h_initialize());

        check_ck_rv("Unable to register token prompt hook.",
                    pkcs11h_setTokenPromptHook(
                            pkcs11h_token_prompt, nullptr));

        check_ck_rv("Unable to register pin prompt hook.",
                    pkcs11h_setPINPromptHook(
                            pkcs11h_pin_prompt, nullptr));

        check_ck_rv("Unable to register slot event hook.",
                    pkcs11h_setSlotEventHook(
                            pkcs11h_slot_event, nullptr));


    }

    void terminate() {
        check_ck_rv("Unable to terminate PKCS11 library.",
                    pkcs11h_terminate());
    }

    void add_provider(const std::u8string_view &reference, const std::u8string_view &provider) {
        check_ck_rv("Unable to register provider.",
                    pkcs11h_addProvider(
                            reinterpret_cast<const char *>(reference.data()),
                            reinterpret_cast<const char *>(provider.data()),
                            FALSE,
                            PKCS11H_PRIVATEMODE_MASK_AUTO,
                            PKCS11H_SLOTEVENT_METHOD_AUTO,
                            0,
                            FALSE
                    ));
    }

    void remove_provider(const std::u8string_view &reference) {
        check_ck_rv("Unable to remove provider.",
                    pkcs11h_removeProvider(
                            reinterpret_cast<const char *>(reference.data())));
    }

    void set_pin_callback(std::function<bool(std::u8string &)> callback) {
        pin_callback = std::move(callback);
    }

    void set_slot_callback(std::function<void()> callback) {
        slot_callback = std::move(callback);
    }

    std::vector<RSACertificateInfo> get_certificates() {

        std::vector<RSACertificateInfo> cert_infos;

        pkcs11h_certificate_id_list_t cert_ids_ptr{nullptr};

        check_ck_rv("Unable to get certificates.",
                    pkcs11h_certificate_enumCertificateIds(
                            PKCS11H_ENUM_METHOD_CACHE,
                            nullptr,
                            PKCS11H_PROMPT_MASK_ALLOW_ALL,
                            nullptr,
                            &cert_ids_ptr));

        std::unique_ptr<pkcs11h_certificate_id_list_s, decltype(&pkcs11h_certificate_freeCertificateIdList)>
                cert_ids(cert_ids_ptr, &pkcs11h_certificate_freeCertificateIdList);

        for (auto cert_id = cert_ids.get(); cert_id != nullptr; cert_id = cert_id->next) {

            pkcs11h_certificate_t cert_ptr{nullptr};

            check_ck_rv("Unable to create cert_ptr.",
                        pkcs11h_certificate_create(
                                cert_id->certificate_id,
                                nullptr,
                                PKCS11H_PROMPT_MASK_ALLOW_ALL,
                                PKCS11H_PIN_CACHE_INFINITE,
                                &cert_ptr));

            std::unique_ptr<pkcs11h_certificate_s, decltype(&pkcs11h_certificate_freeCertificate)>
                    cert(cert_ptr, &pkcs11h_certificate_freeCertificate);

            size_t certificate_size{c_max_certificate_size};
            auto certificate_blob{std::make_unique<unsigned char[]>(certificate_size)};

            check_ck_rv("Unable to get cert_ptr blob.",
                        pkcs11h_certificate_getCertificateBlob(
                                cert.get(),
                                certificate_blob.get(),
                                &certificate_size));

            std::unique_ptr<BIO, decltype(&BIO_free)> bio(
                    BIO_new_mem_buf(
                            certificate_blob.get(),
                            static_cast<int>(certificate_size)),
                    &BIO_free);

            X509 *x509_ptr{nullptr};

            d2i_X509_bio(bio.get(), &x509_ptr);

            std::unique_ptr<X509, decltype(&X509_free)> x509(
                    x509_ptr,
                    &X509_free);

            RSACertificateInfo cert_info;

            cert_info.set_id({cert_id->certificate_id->attrCKA_ID,
                              cert_id->certificate_id->attrCKA_ID_size});

            cert_info.set_common_name(x509_get_common_name(*x509));
            cert_info.set_rsa_modulus(x509_get_rsa_modulus(*x509));

            cert_infos.push_back(cert_info);
        }

        return cert_infos;
    }
}
