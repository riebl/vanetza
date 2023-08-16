#include <gtest/gtest.h>
#include <vanetza/security/tests/check_header_field.hpp>
#include <vanetza/security/tests/check_list.hpp>
#include <vanetza/security/tests/check_payload.hpp>
#include <vanetza/security/tests/check_secured_message.hpp>
#include <vanetza/security/tests/check_trailer_field.hpp>

namespace vanetza
{
namespace security
{
namespace v2
{

void check(const SecuredMessage& expected, const SecuredMessage& actual)
{
    SCOPED_TRACE("v2::SecuredMessage");
    check(expected.header_fields, actual.header_fields);
    check(expected.trailer_fields, actual.trailer_fields);
    check(expected.payload, actual.payload);
}

} // namespace v2
} // namespace security
} // namespace vanetza
