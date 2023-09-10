#pragma once

#include <memory>
#include <span>
#include <map>

#include "Core/RandomNumberGenerator.h"

namespace Shamir
{
    std::map<uint8_t, Base::ZBytes> create_shares(
            Core::RandomNumberGenerator &rng,
            std::span<const uint8_t> secret,
            uint8_t m,
            uint8_t n);

    Base::ZBytes recombine_shares(
            const std::map<uint8_t, Base::ZBytes> &k,
            uint8_t m);
};