#include <gtest/gtest.h>
#include <vanetza/security/tests/check_ecc_point.hpp>
#include <vanetza/security/tests/check_signature.hpp>
#include <vanetza/security/tests/check_visitor.hpp>

namespace vanetza
{
namespace security
{

void check(const EcdsaSignature& expected, const EcdsaSignature& actual)
{
    check(expected.R, actual.R);
    EXPECT_EQ(expected.s, actual.s);
}

void check(const Signature& expected, const Signature& actual)
{
    ASSERT_EQ(get_type(expected), get_type(actual));
    boost::apply_visitor(check_visitor<Signature>(), expected, actual);
}

} // namespace security
} // namespace vanetza
