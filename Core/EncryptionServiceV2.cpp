#include "EncryptionServiceV2.h"

#include <algorithm>

#include "Crypto/Crypto.h"
#include "Base/Encoding.h"
#include "Base/ByteSplitter.h"

static constexpr const std::size_t c_padding_block_size = 24;
static constexpr const std::size_t c_sign_nonce_size = 16;
static constexpr const std::size_t c_aes_gcm_key_size = 32;
static constexpr const std::size_t c_aes_gcm_iv_size = 12;
static constexpr const std::size_t c_aes_gcm_tag_size = 16;

Base::ZBytes Core::EncryptionServiceV2::encrypt(
        std::string_view plain) const
{
    Base::ZBytes nonce(c_sign_nonce_size);

    m_rng->generate_random(nonce);

    const auto nonce_string = Base::Encoding::encode_base64_url_no_padding(nonce).append(m_salt);

    const auto seed = m_entropy_source->get_seed(nonce_string, c_aes_gcm_key_size + c_aes_gcm_iv_size);

    Core::ByteSplitter seed_splitter(seed);

    const auto key = seed_splitter.next(c_aes_gcm_key_size);
    const auto iv = seed_splitter.next(c_aes_gcm_iv_size);

    const auto padding_size = (c_padding_block_size - (plain.size() % c_padding_block_size)) % c_padding_block_size;

    Base::ZBytes plain_bytes;

    plain_bytes.reserve(plain.size() + padding_size);

    plain_bytes.insert(plain_bytes.end(), plain.begin(), plain.end());
    plain_bytes.insert(plain_bytes.end(), padding_size, 0);

    Base::ZBytes tag(c_aes_gcm_tag_size);

    const auto cipher = Crypto::encrypt_aes_256_gcm(key, iv, plain_bytes, tag);

    Base::ZBytes body;

    body.insert(body.end(), nonce.begin(), nonce.end());
    body.insert(body.end(), tag.begin(), tag.end());
    body.insert(body.end(), cipher.begin(), cipher.end());

    return body;
}

Core::EncryptionServiceV2::EncryptionServiceV2(
        std::shared_ptr<Core::EntropySource> entropy_source,
        std::shared_ptr<Core::RandomNumberGenerator> rng,
        std::string_view salt)
        : m_entropy_source{std::move(entropy_source)},
          m_rng {std::move(rng)},
          m_salt {salt}
{
    if (!m_entropy_source)
        throw std::invalid_argument("entropy_source is null.");

    if (!m_rng)
        throw std::invalid_argument("rng is null.");
}

Base::ZString Core::EncryptionServiceV2::decrypt(std::span<const uint8_t> body) const {

    Core::ByteSplitter body_splitter(body);

    const auto nonce = body_splitter.next(c_sign_nonce_size);
    const auto tag = body_splitter.next(c_aes_gcm_tag_size);
    const auto cipher = body_splitter.last();

    const auto nonce_string = Base::Encoding::encode_base64_url_no_padding(nonce).append(m_salt);

    const auto seed = m_entropy_source->get_seed(nonce_string, c_aes_gcm_key_size + c_aes_gcm_iv_size);

    Core::ByteSplitter seed_splitter(seed);

    const auto key = seed_splitter.next(c_aes_gcm_key_size);
    const auto iv = seed_splitter.next(c_aes_gcm_iv_size);

    auto plain = Crypto::decrypt_aes_256_gcm(key, iv, cipher, tag);

    const auto padding_start = std::find_if(
            plain.rbegin(), plain.rend(),
            [] (const uint8_t b) -> bool { return b != 0; }).base();

    Base::ZString text(plain.begin(), padding_start);

    return text;
}
