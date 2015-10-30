#ifndef CHECK_PAYLOAD_HPP_YNRGOKGC
#define CHECK_PAYLOAD_HPP_YNRGOKGC

#include <gtest/gtest.h>
#include <vanetza/security/payload.hpp>

namespace vanetza
{
namespace security
{

inline void check(const Payload& expected, const Payload& actual)
{
    EXPECT_EQ(expected.type, actual.type);
    EXPECT_EQ(expected.buffer, actual.buffer);
}

} // namespace security
} // namespace vanetza

#endif /* CHECK_PAYLOAD_HPP_YNRGOKGC */

