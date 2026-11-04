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

KeyTag::KeyTag(const Sha256Hmac& hmac)
{
    static_assert(length <= Sha256Hmac::length, "tag exceeds HMAC-SHA256");
    std::copy_n(hmac.octets.begin(), octets.size(), octets.begin());
}

bool operator==(const HmacKey& lhs, const HmacKey& rhs)
{
    return lhs.octets == rhs.octets;
}

bool operator!=(const HmacKey& lhs, const HmacKey& rhs)
{
    return !(lhs == rhs);
}

bool operator==(const Sha256Hmac& lhs, const Sha256Hmac& rhs)
{
    return lhs.octets == rhs.octets;
}

bool operator!=(const Sha256Hmac& lhs, const Sha256Hmac& rhs)
{
    return !(lhs == rhs);
}

bool operator==(const KeyTag& lhs, const KeyTag& rhs)
{
    return lhs.octets == rhs.octets;
}

bool operator!=(const KeyTag& lhs, const KeyTag& rhs)
{
    return !(lhs == rhs);
}

#if defined VANETZA_WITH_OPENSSL
KeyTag create_hmac_tag_openssl(const ByteBuffer& data, const HmacKey& hmacKey)
{
    Sha256Hmac hmac;
    unsigned int len = 0;
    HMAC(EVP_sha256(), hmacKey.octets.data(), static_cast<int>(hmacKey.octets.size()),
         data.data(), data.size(), hmac.octets.data(), &len);
    return KeyTag(hmac);
}
#endif

#if defined VANETZA_WITH_CRYPTOPP
KeyTag create_hmac_tag_cryptopp(const ByteBuffer& data, const HmacKey& hmacKey)
{
    Sha256Hmac hmac;
    CryptoPP::HMAC<CryptoPP::SHA256> mac(hmacKey.octets.data(), hmacKey.octets.size());
    mac.Update(data.data(), data.size());
    mac.Final(hmac.octets.data());
    return KeyTag(hmac);
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
