#pragma once

#include <span>

#include "Base/ZVector.h"

namespace Core
{
    class RandomNumberGenerator
    {
    public:

        virtual void generate_random(std::span<uint8_t> out) = 0;

        virtual ~RandomNumberGenerator();
    };
}
