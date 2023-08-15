#pragma once

#include <functional>
#include <vector>
#include <span>
#include <string>
#include <memory>

#include <Base/ZVector.h>

#include "Core/PublicKeyInfo.h"
#include "Core/PKIProvider.h"

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

    Base::ZBytes generate_random(std::size_t length) const override;

    Base::ZBytes sign(std::span<const uint8_t> id, std::span<const uint8_t> data) const override;

    void set_pin_callback(std::function<bool(std::string &)> callback) override;
    void set_slot_callback(std::function<void()> callback) override;


private:
    bool m_initialized {false};
};
}
