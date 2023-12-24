#include "BIP39EntropySourceInfo.h"

#include "Base/StringUtil.h"

PGS::EntropySourceType PGS::V1::BIP39EntropySourceInfo::type() const {
    return PGS::EntropySourceType::BIP39;
}

std::string PGS::V1::BIP39EntropySourceInfo::to_string() const {

    std::string result;

    result.append(prefix);
    result.append("-");
    result.append("v");
    result.append(std::to_string(static_cast<int>(m_version)));
    result.append("-");
    result.append(token());

    return result;
}

PGS::BIP39Version PGS::V1::BIP39EntropySourceInfo::version() const {
    return m_version;
}

PGS::V1::BIP39EntropySourceInfo::BIP39EntropySourceInfo(PGS::BIP39Version version)
    : m_version(version) {
}



std::optional<std::unique_ptr<PGS::V1::BIP39EntropySourceInfo>> PGS::V1::BIP39EntropySourceInfo::parse(std::string_view s) {

    const auto parts = Base::StringUtil::split(s, '-');

    if (parts.size() != 3)
        return std::nullopt;

    if (parts[0] != prefix)
        return std::nullopt;

    std::unique_ptr<BIP39EntropySourceInfo> result;

    if (parts[1] == "v1")
        result = std::make_unique<BIP39EntropySourceInfo>(BIP39Version::BIP39V1);
    else if (parts[1] == "v2")
        result = std::make_unique<BIP39EntropySourceInfo>(BIP39Version::BIP39V2);

    if (!result)
        return std::nullopt;

    result->set_token(parts[2]);

    return result;
}
