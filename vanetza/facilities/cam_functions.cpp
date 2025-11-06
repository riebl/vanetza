#include <vanetza/asn1/cam.hpp>
#include <vanetza/facilities/cam_functions.hpp>
#include <boost/algorithm/clamp.hpp>
#include <boost/math/constants/constants.hpp>
#include <boost/units/cmath.hpp>
#include <boost/units/systems/si/prefixes.hpp>
#include <boost/units/systems/angle/degrees.hpp>

namespace vanetza
{
namespace facilities
{

using vanetza::units::Angle;

static const auto microdegree = units::degree * units::si::micro;
static const auto tenth_microdegree = units::si::deci * microdegree;

bool similar_heading(Angle a, Angle b, Angle limit)
{
    using namespace boost::units;
    using boost::math::double_constants::pi;

    static const Angle full_circle = 2.0 * pi * si::radian;
    const Angle abs_diff = fmod(abs(a - b), full_circle);
    return abs_diff <= limit || abs_diff >= full_circle - limit;
}

template<typename T, typename U>
long round(const boost::units::quantity<T>& q, const U&)
{
    boost::units::quantity<U> v { q };
    return std::round(v.value());
}

AltitudeConfidence_t to_altitude_confidence(units::Length confidence)
{
    const double alt_con = confidence / units::si::meter;

    if (alt_con < 0 || std::isnan(alt_con)) {
        return AltitudeConfidence_unavailable;
    } else if (alt_con <= 0.01) {
        return AltitudeConfidence_alt_000_01;
    } else if (alt_con <= 0.02) {
        return AltitudeConfidence_alt_000_02;
    } else if (alt_con <= 0.05) {
        return AltitudeConfidence_alt_000_05;
    } else if (alt_con <= 0.1) {
        return AltitudeConfidence_alt_000_10;
    } else if (alt_con <= 0.2) {
        return AltitudeConfidence_alt_000_20;
    } else if (alt_con <= 0.5) {
        return AltitudeConfidence_alt_000_50;
    } else if (alt_con <= 1.0) {
        return AltitudeConfidence_alt_001_00;
    } else if (alt_con <= 2.0) {
        return AltitudeConfidence_alt_002_00;
    } else if (alt_con <= 5.0) {
        return AltitudeConfidence_alt_005_00;
    } else if (alt_con <= 10.0) {
        return AltitudeConfidence_alt_010_00;
    } else if (alt_con <= 20.0) {
        return AltitudeConfidence_alt_020_00;
    } else if (alt_con <= 50.0) {
        return AltitudeConfidence_alt_050_00;
    } else if (alt_con <= 100.0) {
        return AltitudeConfidence_alt_100_00;
    } else if (alt_con <= 200.0) {
        return AltitudeConfidence_alt_200_00;
    } else {
        return AltitudeConfidence_outOfRange;
    }
}

AltitudeValue_t to_altitude_value(units::Length alt)
{
    using boost::units::isnan;
    static_assert(AltitudeValue_oneCentimeter == 1, "AltitudeValue encodes an integer number of centimeters");

    if (!isnan(alt)) {
        alt = boost::algorithm::clamp(alt, -1000.0 * units::si::meter, 8000.0 * units::si::meter);
        return round(alt, units::si::centi * units::si::meter);
    } else {
        return AltitudeValue_unavailable;
    }
}

} // namespace facilities
} // namespace vanetza

#define ASN1_PREFIX ASN1_RELEASE1_PREFIX
#define ITS_RELEASE 1
#include "detail/cam.ipp"
#include "detail/heading.ipp"
#include "detail/path_history.ipp"
#include "detail/reference_position.ipp"

#undef ASN1_PREFIX
#undef ITS_RELEASE

#define ASN1_PREFIX ASN1_RELEASE2_PREFIX
#define ITS_RELEASE 2
#include "detail/cam.ipp"
#include "detail/heading.ipp"
#include "detail/path_history.ipp"
#include "detail/reference_position.ipp"

namespace vanetza
{
namespace facilities
{

bool check_service_specific_permissions(const asn1::r1::Cam& cam, security::CamPermissions ssp)
{
    return check_service_specific_permissions(cam->cam.camParameters, ssp);
}

bool check_service_specific_permissions(const asn1::r2::Cam& cam, security::CamPermissions ssp)
{
    return check_service_specific_permissions(cam->cam.camParameters, ssp);
}

void print_indented(std::ostream& os, const asn1::r1::Cam& cam, const std::string& indent, unsigned start)
{
    print_indented(os, cam.content(), indent, start);
}

void print_indented(std::ostream& os, const asn1::r2::Cam& cam, const std::string& indent, unsigned start)
{
    print_indented(os, cam.content(), indent, start);
}

} // namespace facilities
} // namespace vanetza
