#pragma once

#include <cstdint>
#include <array>
#include <string_view>
#include <span>

#include "Base/ZVector.h"

namespace Core
{
    class EntropySource
    {

    public:
        [[nodiscard]]
        virtual Base::ZBytes get_seed(std::string_view nonce, std::size_t size) const = 0;

        [[nodiscard]]
        virtual std::size_t max_seed_size() const = 0;

        virtual ~EntropySource();
    };

}
