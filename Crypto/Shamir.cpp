#include "Shamir.h"

#include "Crypto/GF256.h"

static uint8_t F(const uint8_t x, std::span<const uint8_t> a) {

    uint8_t sum {0};

    for (std::size_t i = a.size(); i > 0; --i)
    {
        sum = GF256::add(GF256::multiply(sum, x), a[i - 1]);
    }

    return sum;
}

static uint8_t L(const std::size_t i, std::span<const uint8_t> u) {

    uint8_t prod {1};

    for (std::size_t j = 0; j < u.size(); j++)
    {
        if (i != j) {
            prod = GF256::multiply(prod, GF256::divide(u[j], GF256::add(u[i], u[j])));
        }
    }

    return prod;
}

static uint8_t I(std::span<const uint8_t> u, std::span<const uint8_t> v) {

    uint8_t sum {0};

    for (std::size_t i = 0; i < u.size(); ++i) {
        sum = GF256::add(sum, GF256::multiply(L(i, u), v[i]));
    }

    return sum;
}

std::map<uint8_t, Base::ZBytes>
Shamir::create_shares(
         Core::RandomNumberGenerator &rng,
         std::span<const uint8_t> secret,
         const uint8_t m,
         const uint8_t n)
{
    if (m == 0)
        throw std::invalid_argument("m can not be zero.");

    if (n < m)
        throw std::invalid_argument("n can not be less than m.");

    std::map<uint8_t, Base::ZBytes> shares;

    for (const auto s : secret) {

        Base::ZBytes a(m);

        a[0] = s;

        rng.generate_random({a.begin() + 1, a.end()});

        for (uint8_t x = n; x > 0; --x) {
            shares[x].push_back(F(x, a));
        }
    }

    return shares;
}

Base::ZBytes Shamir::recombine_shares(
         const std::map<uint8_t, Base::ZBytes> &shares,
         const uint8_t m) {

    if (m == 0)
        throw std::invalid_argument("m can not be zero.");

    if (shares.size() < m)
        throw std::invalid_argument("The number of shares provided is less than m.");

    Base::ZBytes keys;

    keys.reserve(m);

    for (auto it = shares.begin(); keys.size() < m; ++it) {
        keys.push_back(it->first);
    }

    const auto secret_size = shares.at(keys[0]).size();

    for (const auto key: keys) {
        if (shares.at(key).size() != secret_size) {
            throw std::invalid_argument("The sizes of the shares are different.");
        }
    }

    Base::ZBytes secret;

    secret.reserve(secret_size);

    for (std::size_t i = 0; i < secret_size; ++i) {

        Base::ZBytes values;

        values.reserve(keys.size());

        for (const auto key: keys) {
            values.push_back(shares.at(key)[i]);
        }

        secret.push_back(I(keys, values));
    }

    return secret;
}
