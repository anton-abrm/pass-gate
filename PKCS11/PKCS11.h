#pragma once

#include <functional>
#include <vector>
#include <span>
#include <string>

#include <PKCS11/RSACertificateInfo.h>

namespace PKCS11 {

    void initialize();
    void terminate();

    void add_provider(const std::u8string_view &reference,
                      const std::u8string_view &provider);

    void remove_provider(const std::u8string_view &reference);

    std::vector<RSACertificateInfo> get_certificates();

    void * get_certificate(const std::span<const uint8_t> &id);
    void free_certificate(void * cert);

    std::vector<uint8_t> encrypt(void *cert, const std::span<const uint8_t> &data);
    std::vector<uint8_t> decrypt(void *cert, const std::span<const uint8_t> &data);
    std::vector<uint8_t> sign(void * cert, const std::span<const uint8_t> &data);

    void set_pin_callback(std::function<bool(std::u8string &)> callback);
    void set_slot_callback(std::function<void()> callback);
}