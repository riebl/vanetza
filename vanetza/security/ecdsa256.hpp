#ifndef ECDSA256_HPP_IOXLJFVZ
#define ECDSA256_HPP_IOXLJFVZ

#include <array>
#include <cstdint>

namespace vanetza
{
namespace security
{

// forward declaration
struct Uncompressed;

namespace ecdsa256
{

constexpr unsigned digest_octets = 32;

struct PublicKey
{
    std::array<uint8_t, digest_octets> x;
    std::array<uint8_t, digest_octets> y;
};

struct PrivateKey
{
    std::array<uint8_t, digest_octets> key;
};

struct KeyPair
{
    PrivateKey private_key;
    PublicKey public_key;
};

/**
 * Create generic public key from uncompressed ECC point
 * \param unc Uncompressed ECC point
 * \return public key
 */
PublicKey create_public_key(const Uncompressed&);

} // namespace ecdsa256
} // namespace security
} // namespace vanetza

#endif /* ECDSA256_HPP_IOXLJFVZ */

