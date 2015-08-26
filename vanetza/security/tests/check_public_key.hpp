#ifndef CHECK_PUBLIC_KEY_HPP_3HUSMPTE
#define CHECK_PUBLIC_KEY_HPP_3HUSMPTE

#include <gtest/gtest.h>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/tests/check_ecc_point.hpp>
#include <vanetza/security/tests/check_visitor.hpp>

namespace vanetza
{
namespace security
{

inline void check(const ecdsa_nistp256_with_sha256& expected, const ecdsa_nistp256_with_sha256& actual)
{
    check(expected.public_key, actual.public_key);
}

inline void check(const ecies_nistp256& expected, const ecies_nistp256& actual)
{
    EXPECT_EQ(expected.supported_symm_alg, actual.supported_symm_alg);
    check(expected.public_key, actual.public_key);
}

inline void check(const PublicKey& expected, const PublicKey& actual)
{
    ASSERT_EQ(get_type(expected), get_type(actual));
    boost::apply_visitor(check_visitor<PublicKey>(), expected, actual);
}

} // namespace security
} // namespace vanetza

#endif /* CHECK_PUBLIC_KEY_HPP_3HUSMPTE */

