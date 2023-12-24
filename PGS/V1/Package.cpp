#include "Package.h"

#include "Base/Encoding.h"
#include "Base/StringUtil.h"

#include <vector>

static const std::string c_magic = "pgs-v1";

std::optional<std::unique_ptr<PGS::V1::Package>> PGS::V1::Package::parse(std::string_view value) {

    const auto parts = Base::StringUtil::split(value, '.');

    if (parts.size() != 4)
        return std::nullopt;

    if (parts[0] != c_magic)
        return std::nullopt;

    auto entropy_source = EntropySourceInfo::parse(parts[1]);
    if (!entropy_source)
        return std::nullopt;

    auto encryption = EncryptionInfo::parse(parts[2]);
    if (!encryption)
        return std::nullopt;

    auto body = Base::Encoding::decode_base64_any(parts[3]);
    if (!body)
        return std::nullopt;

    auto package = std::make_unique<Package>();

    package->set_entropy_source(std::move(entropy_source.value()));
    package->set_encryption(std::move(encryption.value()));
    package->set_body(body.value());

    return package;
}

std::string PGS::V1::Package::to_string() const {

    if (!m_entropy_source)
        throw std::logic_error("Entropy source is null.");

    if (!m_encryption)
        throw std::logic_error("Encryption is null.");

    std::string s;

    s.append(c_magic);
    s.append(".");
    s.append(m_entropy_source->to_string());
    s.append(".");
    s.append(m_encryption->to_string());
    s.append(".");
    s.append(Base::Encoding::encode_base64_url_no_padding(m_body));

    return s;
}

void PGS::V1::Package::set_entropy_source(std::shared_ptr<EntropySourceInfo> info) {
    m_entropy_source = std::move(info);
}

void PGS::V1::Package::set_body(std::span<const uint8_t> body) {
    m_body.assign(body.begin(), body.end());
}

std::shared_ptr<PGS::V1::EntropySourceInfo> PGS::V1::Package::entropy_source() {
    return m_entropy_source;
}

std::vector<uint8_t> PGS::V1::Package::body() const {
    return m_body;
}

void PGS::V1::Package::set_encryption(std::shared_ptr<EncryptionInfo> encryption) {
    m_encryption = std::move(encryption);
}

std::shared_ptr<PGS::V1::EncryptionInfo> PGS::V1::Package::encryption() {
    return m_encryption;
}


