#include "PKCS11Provider.h"

#include <algorithm>
#include <memory>
#include <dlfcn.h>

#include <openssl/x509.h>
#include <openssl/asn1.h>

#include <pkcs11-helper-1.0/pkcs11.h>
#include <pkcs11-helper-1.0/pkcs11h-certificate.h>

static constexpr size_t c_max_certificate_size = 4096;
static constexpr size_t c_max_signature_size = 4096;

static std::function<bool(std::string &)> pin_callback;
static std::string g_provider;

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

static void check_ck_rv(const char *message, CK_RV rv) {
    if (rv != CKR_OK)
        throw std::runtime_error(
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

    std::string pass;

    if (!pin_callback(pass))
        return false;

    if (pin_max < pass.size())
        throw std::logic_error("Password too long");

    pass.copy(pin, pass.size());

    pin[pass.size()] = '\0';

    return true;
}

static int generate_random_internal(const char *pkcs11_path, int reader_index, unsigned char *random_data, size_t random_length) {

    int error_code = 1;

    CK_FUNCTION_LIST pkcs11 = {0};
    CK_SESSION_HANDLE session = NULL_PTR;
    bool pkcs11_initialized = false;

    void *pkcs11_handle = dlopen(pkcs11_path, RTLD_LAZY);

    if (!pkcs11_handle) {
        goto clean;
    }

    pkcs11_initialized = (pkcs11.C_Initialize = (CK_C_Initialize) dlsym(pkcs11_handle, "C_Initialize")) &&
                         (pkcs11.C_OpenSession = (CK_C_OpenSession) dlsym(pkcs11_handle, "C_OpenSession")) &&
                         (pkcs11.C_GenerateRandom = (CK_C_GenerateRandom) dlsym(pkcs11_handle, "C_GenerateRandom")) &&
                         (pkcs11.C_CloseSession = (CK_C_CloseSession) dlsym(pkcs11_handle, "C_CloseSession")) &&
                         (pkcs11.C_Finalize = (CK_C_Finalize) dlsym(pkcs11_handle, "C_Finalize"));

    if (!pkcs11_initialized) {
        goto clean;
    }

    if ((*pkcs11.C_OpenSession)(reader_index, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session) != CKR_OK)
        goto clean;

    if ((*pkcs11.C_GenerateRandom)(session, random_data, random_length) != CKR_OK)
        goto clean;

    error_code = 0;

    clean:

    if (pkcs11.C_CloseSession && session)
        (*pkcs11.C_CloseSession)(session);

    if (pkcs11_handle)
        dlclose(pkcs11_handle);

    return error_code;
}

namespace PKI {

    void PKCS11Provider::initialize(std::string_view provider) {

        check_ck_rv("Unable to initialize PKI library.",
                    pkcs11h_initialize());

        check_ck_rv("Unable to register token prompt hook.",
                    pkcs11h_setTokenPromptHook(
                            pkcs11h_token_prompt, nullptr));

        check_ck_rv("Unable to register pin prompt hook.",
                    pkcs11h_setPINPromptHook(
                            pkcs11h_pin_prompt, nullptr));


        check_ck_rv("Unable to register provider.",
                    pkcs11h_addProvider(
                            "",
                            std::string(provider).c_str(),
                            FALSE,
                            PKCS11H_PRIVATEMODE_MASK_AUTO,
                            PKCS11H_SLOTEVENT_METHOD_AUTO,
                            0,
                            FALSE
                    ));

        g_provider = provider;

        m_initialized = true;
    }

    void PKCS11Provider::terminate() {
        check_ck_rv("Unable to terminate PKI library.",
                    pkcs11h_terminate());
        m_initialized = false;
    }

    void PKCS11Provider::set_pin_callback(std::function<bool(std::string &)> callback) {
        pin_callback = std::move(callback);
    }

    std::vector<Core::PublicKeyInfo> PKCS11Provider::get_certificates() const {

        std::vector<Core::PublicKeyInfo> cert_infos;

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

            int pk_nid = 0;

            X509_get_signature_info(x509.get(), NULL, &pk_nid, NULL, NULL);

            if (pk_nid != NID_rsaEncryption)
                continue;

            Core::PublicKeyInfo cert_info;

            const auto id = std::span<const uint8_t>(
                    cert_id->certificate_id->attrCKA_ID,
                    cert_id->certificate_id->attrCKA_ID_size);

            const auto rsa_modulus = x509_get_rsa_modulus(*x509);
            const auto common_name = x509_get_common_name(*x509);

            std::array<uint8_t, Core::PublicKeyInfo::public_key_token_size> public_key_token {0};

            std::copy_n(
                    rsa_modulus.begin(),
                    public_key_token.size(),
                    public_key_token.begin());

            cert_info.set_id(id);
            cert_info.set_common_name(common_name);
            cert_info.set_public_key_token(public_key_token);

            cert_infos.push_back(std::move(cert_info));
        }

        return cert_infos;
    }

    Base::ZBytes PKCS11Provider::sign(std::span<const uint8_t> id, std::span<const uint8_t> data) const
    {
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

        if (result == nullptr)
            throw std::runtime_error("Certificate not found.");

        size_t sign_size{c_max_signature_size};

        Base::ZBytes sign_blob(sign_size);

        check_ck_rv("Unable to sign blob.",
                    pkcs11h_certificate_sign(
                            reinterpret_cast<pkcs11h_certificate_t>(result),
                            CKM_SHA512_RSA_PKCS,
                            data.data(),
                            data.size(),
                            sign_blob.data(),
                            &sign_size
                    ));

        sign_blob.resize(static_cast<int>(sign_size));

        return sign_blob;
    }

   std::shared_ptr<PKCS11Provider> PKCS11Provider::instance()
    {
        static std::shared_ptr<PKCS11Provider> instance { new PKCS11Provider() };

        return instance;
    }

    bool PKCS11Provider::is_initialized() const {
        return m_initialized;
    }

    void PKCS11Provider::generate_random(std::span<uint8_t> span) {

        if (g_provider.empty())
            throw std::runtime_error("Provider is not set");

        if (generate_random_internal(reinterpret_cast<const char *>(g_provider.c_str()), 0, span.data(), span.size()) != 0) {
            throw std::runtime_error("Unable to generate random");
        }
    }

    PKCS11Provider::PKCS11Provider() = default;
}
