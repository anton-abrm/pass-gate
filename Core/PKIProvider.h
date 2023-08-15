#pragma once

#include <functional>
#include <vector>
#include <span>
#include <string>
#include <memory>

#include "Base/ZVector.h"

#include "PublicKeyInfo.h"
#include "RandomNumberGenerator.h"

namespace Core {

class PKIProvider
{

protected:
    PKIProvider();

public:

    virtual void initialize(std::string_view provider) = 0;
    virtual void terminate() = 0;
    virtual bool is_initialized() const = 0;

    virtual std::vector<PublicKeyInfo> get_certificates() const = 0;

    virtual Base::ZBytes sign(std::span<const uint8_t> id, std::span<const uint8_t> data) const = 0;

    virtual void set_pin_callback(std::function<bool(std::string &)> callback) = 0;
    virtual void set_slot_callback(std::function<void()> callback) = 0;

    virtual ~PKIProvider();
};

}

