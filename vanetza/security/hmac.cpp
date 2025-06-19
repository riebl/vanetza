#include <vanetza/security/hmac.hpp>
#include <cryptopp/osrng.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

namespace vanetza
{
namespace security
{

KeyTag create_hmac_tag(const ByteBuffer& data, const HmacKey& hmacKey)
{
    KeyTag keyTag;

    // Calculate tag.
    CryptoPP::HMAC<CryptoPP::SHA256> mac(hmacKey.data(), hmacKey.size());
    unsigned char tag[hmacKey.size()];
    mac.Update(data.data(), data.size());
    mac.Final(tag);

    // Tag is truncated to leftmost 128 bits.
    std::copy_n(tag, keyTag.size(), keyTag.data());
    return keyTag;
}

} // namespace security
} // namespace vanetza
