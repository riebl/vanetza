#include <vanetza/security/hmac.hpp>
#include <algorithm>
#include <array>

#if defined VANETZA_WITH_OPENSSL
#include <openssl/hmac.h>
#endif

#if defined VANETZA_WITH_CRYPTOPP
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#endif

namespace vanetza
{
namespace security
{

#if defined VANETZA_WITH_OPENSSL
KeyTag create_hmac_tag_openssl(const ByteBuffer& data, const HmacKey& hmacKey)
{
    KeyTag keyTag;
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> tag;
    unsigned int len = 0;
    HMAC(EVP_sha256(), hmacKey.data(), static_cast<int>(hmacKey.size()),
         data.data(), data.size(), tag.data(), &len);
    std::copy_n(tag.data(), keyTag.size(), keyTag.data());
    return keyTag;
}
#endif

#if defined VANETZA_WITH_CRYPTOPP
KeyTag create_hmac_tag_cryptopp(const ByteBuffer& data, const HmacKey& hmacKey)
{
    KeyTag keyTag;
    std::array<std::uint8_t, 32> tag;
    CryptoPP::HMAC<CryptoPP::SHA256> mac(hmacKey.data(), hmacKey.size());
    mac.Update(data.data(), data.size());
    mac.Final(tag.data());
    std::copy_n(tag.data(), keyTag.size(), keyTag.data());
    return keyTag;
}
#endif

KeyTag create_hmac_tag(const ByteBuffer& data, const HmacKey& hmacKey)
{
#if defined VANETZA_WITH_OPENSSL
    return create_hmac_tag_openssl(data, hmacKey);
#elif defined VANETZA_WITH_CRYPTOPP
    return create_hmac_tag_cryptopp(data, hmacKey);
#else
#   warn "no HMAC implementation available"
    return KeyTag {};
#endif
}

} // namespace security
} // namespace vanetza
