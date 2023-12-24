#include "EncryptionInfo.h"

#include "Base/StringUtil.h"

std::string PGS::V1::EncryptionInfo::to_string() const {

    std::string result;

    result.append(prefix);
    result.append("-");
    result.append("v");
    result.append(std::to_string(static_cast<int>(m_version)));

    return result;
}

PGS::EncryptionVersion PGS::V1::EncryptionInfo::version() const {
    return m_version;
}

PGS::V1::EncryptionInfo::EncryptionInfo(PGS::EncryptionVersion version)
    : m_version(version) {
}

std::optional<std::unique_ptr<PGS::V1::EncryptionInfo>> PGS::V1::EncryptionInfo::parse(std::string_view s) {

    const auto parts = Base::StringUtil::split(s, '-');

    if (parts.size() != 2)
        return std::nullopt;

    if (parts[0] != prefix)
        return std::nullopt;

    std::unique_ptr<EncryptionInfo> result;

    if (parts[1] == "v1")
        result = std::make_unique<EncryptionInfo>(EncryptionVersion::EncryptionV1);
    else if (parts[1] == "v2")
        result = std::make_unique<EncryptionInfo>(EncryptionVersion::EncryptionV2);

    if (!result)
        return std::nullopt;

    return result;
}