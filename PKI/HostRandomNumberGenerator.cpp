#include "HostRandomNumberGenerator.h"

#include <openssl/rand.h>



std::shared_ptr<PKI::HostRandomNumberGenerator> PKI::HostRandomNumberGenerator::instance() {
    static std::shared_ptr<HostRandomNumberGenerator> instance { new HostRandomNumberGenerator() };

    return instance;
}

void PKI::HostRandomNumberGenerator::generate_random(std::span<uint8_t> out) {
    if (1 != RAND_bytes(out.data(), static_cast<int>(out.size())))
        throw std::runtime_error("Unable to generate random.");
}

PKI::HostRandomNumberGenerator::HostRandomNumberGenerator() = default;