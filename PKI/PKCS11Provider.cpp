#include "PKCS11Provider.h"

#include <algorithm>
#include <memory>

#if _WIN32
    #include <Windows.h>
#else
    #include <dlfcn.h>
#endif

#include "Base/ZString.h"

static constexpr size_t c_max_signature_size = 4096;

static std::runtime_error create_error(const std::string &error_message, const CK_RV rv) {
    return std::runtime_error(error_message + " " + PKI::PKCS11Helper::get_message(rv));
}

static std::runtime_error create_error(const std::string &error_message) {
    return std::runtime_error(error_message);
}

static CK_OBJECT_HANDLE find_private_key(CK_FUNCTION_LIST_PTR pkcs11_ptr, CK_SESSION_HANDLE session_handle, std::span<const uint8_t> id) {

    CK_OBJECT_CLASS object_class = CKO_PRIVATE_KEY;
    CK_BBOOL true_bool = CK_TRUE;

    std::array search_attributes = {
        CK_ATTRIBUTE { CKA_CLASS, &object_class, sizeof(object_class)},
        CK_ATTRIBUTE { CKA_SIGN, &true_bool, sizeof(true_bool)},
        CK_ATTRIBUTE { CKA_ID, const_cast<CK_BYTE_PTR>(id.data()), static_cast<CK_ULONG>(id.size())},
    };

    if (const auto rv = pkcs11_ptr->C_FindObjectsInit(session_handle, search_attributes.data(), static_cast<CK_ULONG>(search_attributes.size())); rv != CKR_OK) {
        throw create_error("Unable to initialize the search of the private key.", rv);
    }

    CK_OBJECT_HANDLE private_key_handle{ CK_INVALID_HANDLE };
    CK_ULONG objects_found {0};

    if (const auto rv = pkcs11_ptr->C_FindObjects(session_handle, &private_key_handle, 1, &objects_found); rv != CKR_OK) {
        throw create_error("An error occurred while searching the private key.", rv);
    }

    if (const auto rv =pkcs11_ptr->C_FindObjectsFinal(session_handle); rv != CKR_OK) {
        throw create_error("Unable to finalise the search of the private key.", rv);
    }

    if (objects_found) {
        return private_key_handle;
    }

    return CK_INVALID_HANDLE;
}

namespace PKI {

    void PKCS11Provider::initialize(std::string_view provider) {

        try {

#if _WIN32
            m_pkcs11_handle = LoadLibraryA(std::string(provider).c_str());
#else
            m_pkcs11_handle = dlopen(std::string(provider).c_str(), RTLD_LAZY);
#endif
            if (!m_pkcs11_handle) {
                throw create_error("Unable to obtain PKCS11 library handle.");
            }

            // https://pubs.opengroup.org/onlinepubs/009695399/functions/dlsym.html
            CK_C_GetFunctionList get_fn_list_ptr {nullptr};

#if _WIN32
            if (*(void **)(&get_fn_list_ptr) = GetProcAddress(static_cast<HMODULE>(m_pkcs11_handle), "C_GetFunctionList"); !get_fn_list_ptr) {
#else
            if (*(void **)(&get_fn_list_ptr) = dlsym(m_pkcs11_handle, "C_GetFunctionList"); !get_fn_list_ptr) {
#endif
                throw create_error("Unable to find C_GetFunctionList.");
            }

            if (const auto rv = get_fn_list_ptr(&m_pkcs11_ptr); rv != CKR_OK) {
                throw create_error("Unable to bind function pointers.", rv);
            }

            if (const auto rv = m_pkcs11_ptr->C_Initialize(NULL_PTR); rv != CKR_OK) {
                throw create_error("Unable to initialize PKCS11 library.", rv);
            }

            CK_ULONG slot_count {1};
            CK_SLOT_ID slot_id {0};

            if (auto rv = m_pkcs11_ptr->C_GetSlotList(CK_TRUE, &slot_id, &slot_count); rv != CKR_OK) {
                if (rv == CKR_BUFFER_TOO_SMALL)
                    throw create_error("Multiple tokens are not supported.");

                throw create_error("Unable to obtain the slot list.", rv);
            }

            if (slot_count == 0) {
                throw create_error("The token is not present.");
            }

            if (const auto rv = m_pkcs11_ptr->C_OpenSession(slot_id, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &m_session_handle); rv != CKR_OK) {
                throw create_error("Unable to open PKCS11 session.", rv);
            }

            m_initialized = true;
        }
        catch (const std::runtime_error&) {
            terminate();
            throw;
        }
    }

    void PKCS11Provider::terminate() {

        m_initialized = false;

        if (m_session_handle != CK_INVALID_HANDLE) {
            m_pkcs11_ptr->C_CloseSession(m_session_handle);
            m_session_handle = CK_INVALID_HANDLE;
        }

        if (m_pkcs11_ptr) {
            m_pkcs11_ptr->C_Finalize(NULL_PTR);
            m_pkcs11_ptr = nullptr;
        }

        if (m_pkcs11_handle) {

#if _WIN32
            FreeLibrary(static_cast<HMODULE>(m_pkcs11_handle));
#else
            dlclose(m_pkcs11_handle);
#endif
            m_pkcs11_handle = nullptr;
        }
    }

    void PKCS11Provider::set_pin_callback(std::function<bool(std::string &)> callback) {
        m_pin_callback = std::move(callback);
    }

    std::vector<Core::PublicKeyInfo> PKCS11Provider::get_certificates() const {

        CK_OBJECT_CLASS object_class = CKO_PUBLIC_KEY;

        std::array search_attributes = {
            CK_ATTRIBUTE { CKA_CLASS, &object_class, sizeof(object_class)},
        };

        if (const auto rv = m_pkcs11_ptr->C_FindObjectsInit(m_session_handle, search_attributes.data(),
            static_cast<CK_ULONG>(search_attributes.size())); rv != CKR_OK) {
            throw create_error("Unable to initialize the search of the public key.", rv);
        }

        std::vector<CK_OBJECT_HANDLE> object_handles(256);
        CK_ULONG objects_found {0};

        if (const auto rv = m_pkcs11_ptr->C_FindObjects(m_session_handle, object_handles.data(),
            static_cast<CK_ULONG>(object_handles.size()), &objects_found); rv != CKR_OK) {
            throw create_error("An error occurred while searching the public key.", rv);
        }

        if (const auto rv = m_pkcs11_ptr->C_FindObjectsFinal(m_session_handle); rv != CKR_OK) {
            throw create_error("Unable to finalise the search of the public key.", rv);
        }

        object_handles.resize(objects_found);

        std::vector<Core::PublicKeyInfo> infos;

        for (const auto object_handle: object_handles) {

            std::array attributes = {
                CK_ATTRIBUTE{CKA_ID, NULL_PTR, 0},
                CK_ATTRIBUTE{CKA_LABEL, NULL_PTR, 0},
                CK_ATTRIBUTE{CKA_MODULUS, NULL_PTR, 0},
            };

            if (const auto rv = m_pkcs11_ptr->C_GetAttributeValue(m_session_handle, object_handle, attributes.data(),
                static_cast<CK_ULONG>(attributes.size())); rv != CKR_OK) {
                throw create_error("Unable to get key attributes.", rv);
            }

            std::vector<CK_BYTE> id(attributes[0].ulValueLen);
            attributes[0].pValue = id.data();

            std::vector<CK_UTF8CHAR> label(attributes[1].ulValueLen);
            attributes[1].pValue = label.data();

            std::vector<CK_BYTE> modulus(attributes[2].ulValueLen);
            attributes[2].pValue = modulus.data();

            if (const auto rv = m_pkcs11_ptr->C_GetAttributeValue(m_session_handle, object_handle, attributes.data(),
                static_cast<CK_ULONG>(attributes.size())); rv != CKR_OK) {
                throw create_error("Unable to get key attributes.", rv);
            }

            std::array<uint8_t, Core::PublicKeyInfo::public_key_token_size> public_key_token {0};

            std::copy_n(
                    modulus.begin(),
                    public_key_token.size(),
                    public_key_token.begin());

            Core::PublicKeyInfo pki;

            pki.set_id(id);
            pki.set_common_name({reinterpret_cast<char*>(label.data()), label.size()});
            pki.set_public_key_token(public_key_token);

            infos.push_back(pki);
        }

        return infos;
    }

    Base::ZBytes PKCS11Provider::sign(std::span<const uint8_t> id, std::span<const uint8_t> data) const
    {
        auto private_key_handle = find_private_key(m_pkcs11_ptr, m_session_handle, id);

        if (private_key_handle == CK_INVALID_HANDLE) {

            CK_SESSION_INFO info {};

            if (const auto rv = m_pkcs11_ptr->C_GetSessionInfo(m_session_handle, &info); rv != CKR_OK)
                throw create_error("Unable to get session info.", rv);

            if (info.state != CKS_RO_PUBLIC_SESSION)
                throw create_error("The private key was not found.");

            if (!m_pin_callback)
                throw create_error("There is no pin callback set.");

            std::string password;

            if (!m_pin_callback(password))
                throw create_error("The login operation was cancelled by the user.");

            if (const auto rv = m_pkcs11_ptr->C_Login(m_session_handle, CKU_USER,
                reinterpret_cast<CK_UTF8CHAR_PTR>(password.data()), static_cast<CK_ULONG>(password.size())); rv != CKR_OK)
                throw create_error("Unable to login to SC.", rv);

            private_key_handle = find_private_key(m_pkcs11_ptr, m_session_handle, id);

            if (private_key_handle == CK_INVALID_HANDLE)
                throw create_error("The private key was not found.");
        }

        CK_MECHANISM mechanism = {
            CKM_SHA512_RSA_PKCS, NULL_PTR, 0
        };

        if (const auto rv = m_pkcs11_ptr->C_SignInit(m_session_handle, &mechanism, private_key_handle); rv != CKR_OK) {
            throw create_error("Unable to initialize the sign operation.", rv);
        }

        if (const auto rv = m_pkcs11_ptr->C_SignUpdate(m_session_handle, const_cast<CK_BYTE_PTR>(data.data()),
            static_cast<CK_ULONG>(data.size())); rv != CKR_OK) {
            throw create_error("An error occurred during the sign operation.", rv);
        }

        CK_ULONG sign_size{c_max_signature_size};

        Base::ZBytes sign_blob(sign_size);

        if (const auto rv = m_pkcs11_ptr->C_SignFinal(m_session_handle, sign_blob.data(), &sign_size); rv != CKR_OK) {
            throw create_error("Unable to finalise the sign operation.", rv);
        }

        sign_blob.resize(sign_size);

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
        if (const auto rv = m_pkcs11_ptr->C_GenerateRandom(m_session_handle, span.data(),
            static_cast<CK_ULONG>(span.size())); rv != CKR_OK) {
            throw create_error("Unable to generate random.", rv);
        }
    }

    PKCS11Provider::PKCS11Provider() = default;
}
