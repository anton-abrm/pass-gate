#pragma once


#include "Base/ZVector.h"

namespace Core
{
    class RandomNumberGenerator
    {
    public:
        [[nodiscard]]
        virtual Base::ZBytes generate_random(std::size_t length) const = 0;

        virtual ~RandomNumberGenerator();
    };
}
