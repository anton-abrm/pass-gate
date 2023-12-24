
#include "EntropySourceInfo.h"

#include "Base/StringUtil.h"
#include "PGS/V1/BIP39EntropySourceInfo.h"
#include "PGS/V1/SignatureEntropySourceInfo.h"
#include "PGS/V1/RandomEntropySource.h"

PGS::V1::EntropySourceInfo::~EntropySourceInfo() = default;

std::optional<std::unique_ptr<PGS::V1::EntropySourceInfo>> PGS::V1::EntropySourceInfo::parse(std::string_view s) {

    if (s.starts_with(SignatureEntropySourceInfo::prefix))
        return SignatureEntropySourceInfo::parse(s);

    if (s.starts_with(BIP39EntropySourceInfo::prefix))
        return BIP39EntropySourceInfo::parse(s);

    if (s.starts_with(RandomEntropySource::prefix))
        return RandomEntropySource::parse(s);

    return std::nullopt;
}

std::string PGS::V1::EntropySourceInfo::token() const {
    return m_token;
}

void PGS::V1::EntropySourceInfo::set_token(std::string_view token) {
    m_token = token;
}