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

HmacKey::~HmacKey()
{
    // volatile writes are not optimised away although the key is not read afterwards
    volatile std::uint8_t* octet = octets.data();
    for (std::size_t i = 0; i < octets.size(); ++i) {
        octet[i] = 0;
    }
}

bool operator==(const HmacKey& lhs, const HmacKey& rhs)
{
    return lhs.octets == rhs.octets;
}

bool operator!=(const HmacKey& lhs, const HmacKey& rhs)
{
    return !(lhs == rhs);
}

#if defined VANETZA_WITH_OPENSSL
KeyTag create_hmac_tag_openssl(const ByteBuffer& data, const HmacKey& hmacKey)
{
    KeyTag keyTag;
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> tag;
    unsigned int len = 0;
    HMAC(EVP_sha256(), hmacKey.octets.data(), static_cast<int>(hmacKey.octets.size()),
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
    CryptoPP::HMAC<CryptoPP::SHA256> mac(hmacKey.octets.data(), hmacKey.octets.size());
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
#   warning "no HMAC implementation available"
    return KeyTag {};
#endif
}

} // namespace security
} // namespace vanetza
