#include <vanetza/security/sha.hpp>
#ifdef VANETZA_WITH_CRYPTOPP
#include <cryptopp/sha.h>
#endif
#ifdef VANETZA_WITH_OPENSSL
#include <openssl/sha.h>
#endif
#if defined VANETZA_WITH_PSA && !defined VANETZA_WITH_OPENSSL && !defined VANETZA_WITH_CRYPTOPP
#define VANETZA_SHA_BY_PSA
#include <vanetza/security/psa_wrapper.hpp>
#endif

namespace vanetza
{
namespace security
{

Sha256Digest calculate_sha256_digest(const uint8_t* data, std::size_t len)
{
    Sha256Digest digest;
#if defined VANETZA_WITH_OPENSSL
    static_assert(SHA256_DIGEST_LENGTH == digest.size(), "size of OpenSSL SHA256_DIGEST_LENGTH does not match");
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(digest.data(), &ctx);
#elif defined VANETZA_WITH_CRYPTOPP
    static_assert(CryptoPP::SHA256::DIGESTSIZE == digest.size(), "size of CryptoPP::SHA256 does not match digest");
    CryptoPP::SHA256 hash;
    hash.CalculateDigest(digest.data(), data, len);
#elif defined VANETZA_SHA_BY_PSA
    psa::calculate_hash(PSA_ALG_SHA_256, data, len, digest);
#else
#   error "no SHA256 implementation available"
#endif
    return digest;
}

Sha384Digest calculate_sha384_digest(const uint8_t* data, std::size_t len)
{
    Sha384Digest digest;
#if defined VANETZA_WITH_OPENSSL
    SHA384(data, len, digest.data());
#elif defined VANETZA_WITH_CRYPTOPP
    static_assert(CryptoPP::SHA384::DIGESTSIZE == digest.size(), "size of CryptoPP::SHA384 does not match digest");
    CryptoPP::SHA384 hash;
    hash.CalculateDigest(digest.data(), data, len);
#elif defined VANETZA_SHA_BY_PSA
    psa::calculate_hash(PSA_ALG_SHA_384, data, len, digest);
#else
#   error "no SHA384 implementation available"
#endif
    return digest;
}

bool operator==(const Sha256Hash& lhs, const Sha256Hash& rhs)
{
    return lhs.octets == rhs.octets;
}

bool operator!=(const Sha256Hash& lhs, const Sha256Hash& rhs)
{
    return !(lhs == rhs);
}

bool operator==(const Sha384Hash& lhs, const Sha384Hash& rhs)
{
    return lhs.octets == rhs.octets;
}

bool operator!=(const Sha384Hash& lhs, const Sha384Hash& rhs)
{
    return !(lhs == rhs);
}

} // namespace security
} // namespace vanetza
