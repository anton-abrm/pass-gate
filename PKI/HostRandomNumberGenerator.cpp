#include "HostRandomNumberGenerator.h"

#include <openssl/rand.h>

Base::ZBytes PKI::HostRandomNumberGenerator::generate_random(std::size_t length) const
{
    Base::ZBytes result(length);

    if (1 != RAND_bytes(result.data(), static_cast<int>(length)))
        throw std::runtime_error("Unable to generate random.");

    return result;
}

std::shared_ptr<PKI::HostRandomNumberGenerator> PKI::HostRandomNumberGenerator::instance() {
    static std::shared_ptr<HostRandomNumberGenerator> instance { new HostRandomNumberGenerator() };

    return instance;
}

PKI::HostRandomNumberGenerator::HostRandomNumberGenerator() = default;
