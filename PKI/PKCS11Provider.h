#pragma once

#include <functional>
#include <vector>
#include <span>
#include <string>
#include <memory>

#include <Base/ZVector.h>

#include "Core/PublicKeyInfo.h"
#include "Core/PKIProvider.h"
#include "PKI/PKCS11Helper.h"

namespace PKI {

class PKCS11Provider final : virtual public Core::PKIProvider,
                             virtual public Core::RandomNumberGenerator {

private:
    PKCS11Provider();

public:
    static std::shared_ptr<PKCS11Provider> instance();

    void initialize(std::string_view provider) override;
    void terminate() override;

    std::vector<Core::PublicKeyInfo> get_certificates() const override;
    bool is_initialized() const override;

    void generate_random(std::span<uint8_t>) override;

    Base::ZBytes sign(std::span<const uint8_t> id, std::span<const uint8_t> data) const override;

    void set_pin_callback(std::function<bool(std::string &)> callback) override;

private:

    void * m_pkcs11_handle = nullptr;

    CK_FUNCTION_LIST_PTR m_pkcs11_ptr {nullptr};
    CK_SESSION_HANDLE m_session_handle { CK_INVALID_HANDLE };

    bool m_initialized {false};
    std::function<bool(std::string &)> m_pin_callback;
};
}
