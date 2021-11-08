#pragma once

#include <functional>
#include <vector>
#include <span>
#include <string>
#include <memory>

#include "RSACertificate.h"
#include "RSACertificateInfo.h"

namespace PKCS11 {

    void initialize();
    void terminate();

    void add_provider(const std::u8string_view &reference,
                      const std::u8string_view &provider);

    void remove_provider(const std::u8string_view &reference);

    std::vector<RSACertificateInfo> get_certificates();

    void set_pin_callback(std::function<bool(std::u8string &)> callback);
    void set_slot_callback(std::function<void()> callback);
}