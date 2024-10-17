#include <vanetza/asn1/its/Heading.h>
#include <vanetza/asn1/its/r2/Heading.h>
#include <vanetza/facilities/detail/macros.ipp>
#include <vanetza/units/angle.hpp>

ASSERT_EQUAL_ENUM(HeadingValue_wgs84North);
ASSERT_EQUAL_ENUM(HeadingValue_wgs84East);
ASSERT_EQUAL_ENUM(HeadingValue_wgs84South);
ASSERT_EQUAL_ENUM(HeadingValue_wgs84West);
ASSERT_EQUAL_ENUM(HeadingValue_unavailable);

namespace vanetza
{
namespace facilities
{

bool is_available(const ASN1_PREFIXED(Heading)& hd)
{
    return hd.headingValue != ASN1_PREFIXED(HeadingValue_unavailable);
}

bool similar_heading(const ASN1_PREFIXED(Heading)& a, const ASN1_PREFIXED(Heading)& b, Angle limit)
{
    // HeadingValues are tenth of degree (900 equals 90 degree east)
    static_assert(ASN1_PREFIXED(HeadingValue_wgs84East) == 900, "HeadingValue interpretation fails");

    bool result = false;
    if (is_available(a) && is_available(b)) {
        using vanetza::units::degree;
        const Angle angle_a { a.headingValue / 10.0 * degree };
        const Angle angle_b { b.headingValue / 10.0 * degree };
        result = similar_heading(angle_a, angle_b, limit);
    }

    return result;
}

bool similar_heading(const ASN1_PREFIXED(Heading)& a, Angle b, Angle limit)
{
    bool result = false;
    if (is_available(a)) {
        using vanetza::units::degree;
        result = similar_heading(Angle { a.headingValue / 10.0 * degree}, b, limit);
    }
    return result;
}

} // namespace facilities
} // namespace vanetza
