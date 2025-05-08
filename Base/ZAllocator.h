#pragma once

#include <cstdlib>
#include <limits>
#include <iostream>
#include <vector>
#include <cstring>

#include <openssl/crypto.h>

namespace Base {

    template<class T>
    struct ZAllocator {
        typedef T value_type;

        constexpr ZAllocator() noexcept = default;

        // The current debug mechanism for containers in MSVC STL does need to allocate memory
        // for a separated "proxy" object for each container, which always needs rebinding.
        template<class U> ZAllocator(const ZAllocator<U>&) noexcept {}

        constexpr ZAllocator(const ZAllocator &) noexcept = default;

        T *allocate(std::size_t n) {

            if (n > std::numeric_limits<std::size_t>::max() / sizeof(T))
                throw std::bad_array_new_length();

            auto p = static_cast<T *>(OPENSSL_malloc(n * sizeof(T)));
            if (!p)
                throw std::bad_alloc();

            return p;
        };

        void deallocate(T *p, std::size_t n) noexcept {
            OPENSSL_clear_free(p, n);
        };
    };

    template<class T, class U>
    bool operator==(const ZAllocator<T> &, const ZAllocator<U> &) { return true; }

    template<class T, class U>
    bool operator!=(const ZAllocator<T> &, const ZAllocator<U> &) { return false; }

}