#include "RandomEntropySource.h"


PGS::EntropySourceType PGS::V1::RandomEntropySource::type() const {
    return PGS::EntropySourceType::Random;
}

std::string PGS::V1::RandomEntropySource::to_string() const {

    std::string result;

    result.append(prefix);

    return result;
}

std::optional<std::unique_ptr<PGS::V1::RandomEntropySource>>
PGS::V1::RandomEntropySource::parse(std::string_view s) {

    if (s != prefix)
        return std::nullopt;

    return std::make_unique<PGS::V1::RandomEntropySource>();
}
