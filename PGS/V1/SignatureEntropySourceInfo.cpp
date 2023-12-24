#include "SignatureEntropySourceInfo.h"

#include "Base/StringUtil.h"

PGS::EntropySourceType PGS::V1::SignatureEntropySourceInfo::type() const {
    return PGS::EntropySourceType::Signature;
}

std::string PGS::V1::SignatureEntropySourceInfo::to_string() const {

    std::string result;

    result.append(prefix);
    result.append("-");
    result.append("v");
    result.append(std::to_string(static_cast<int>(m_version)));
    result.append("-");
    result.append(token());

    return result;
}

PGS::SignatureVersion PGS::V1::SignatureEntropySourceInfo::version() const {
    return m_version;
}

PGS::V1::SignatureEntropySourceInfo::SignatureEntropySourceInfo(PGS::SignatureVersion version)
    : m_version(version) {
}

std::optional<std::unique_ptr<PGS::V1::SignatureEntropySourceInfo>>
PGS::V1::SignatureEntropySourceInfo::parse(std::string_view s)
{
    const auto parts = Base::StringUtil::split(s, '-');

    if (parts.size() != 3)
        return std::nullopt;

    if (parts[0] != prefix)
        return std::nullopt;

    std::unique_ptr<SignatureEntropySourceInfo> result;

    if (parts[1] == "v2")
        result = std::make_unique<SignatureEntropySourceInfo>(SignatureVersion::SignatureV2);

    if (!result)
        return std::nullopt;

    result->set_token(parts[2]);

    return result;
}
