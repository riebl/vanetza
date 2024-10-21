#include <vanetza/asn1/its/ReferencePosition.h>
#include <vanetza/asn1/its/r2/ReferencePosition.h>
#include <vanetza/facilities/detail/macros.ipp>
#include <vanetza/geonet/areas.hpp>
#include <vanetza/units/length.hpp>
#include <limits>

namespace vanetza
{
namespace facilities
{

static_assert(Longitude_oneMicrodegreeEast == 10, "Longitude is an integer number of tenth microdegrees");
static_assert(Latitude_oneMicrodegreeNorth == 10, "Latitude is an integer number of tenth microdegrees");

units::Length distance(const ASN1_PREFIXED(ReferencePosition_t)& a, const ASN1_PREFIXED(ReferencePosition_t)& b)
{
    using geonet::GeodeticPosition;
    using units::GeoAngle;

    auto length = units::Length::from_value(std::numeric_limits<double>::quiet_NaN());
    if (is_available(a) && is_available(b)) {
        GeodeticPosition geo_a {
            GeoAngle { a.latitude * tenth_microdegree },
            GeoAngle { a.longitude * tenth_microdegree }
        };
        GeodeticPosition geo_b {
            GeoAngle { b.latitude * tenth_microdegree },
            GeoAngle { b.longitude * tenth_microdegree }
        };
        length = geonet::distance(geo_a, geo_b);
    }
    return length;
}

units::Length distance(const ASN1_PREFIXED(ReferencePosition_t)& a, units::GeoAngle lat, units::GeoAngle lon)
{
    using geonet::GeodeticPosition;
    using units::GeoAngle;

    auto length = units::Length::from_value(std::numeric_limits<double>::quiet_NaN());
    if (is_available(a)) {
        GeodeticPosition geo_a {
            GeoAngle { a.latitude * tenth_microdegree },
            GeoAngle { a.longitude * tenth_microdegree }
        };
        GeodeticPosition geo_b { lat, lon };
        length = geonet::distance(geo_a, geo_b);
    }
    return length;
}

bool is_available(const ASN1_PREFIXED(ReferencePosition)& pos)
{
    return pos.latitude != ASN1_PREFIXED(Latitude_unavailable) && pos.longitude != ASN1_PREFIXED(Longitude_unavailable);
}

void copy(const PositionFix& position, ASN1_PREFIXED(ReferencePosition)& reference_position)
{
    reference_position.longitude = round(position.longitude, tenth_microdegree);
    reference_position.latitude = round(position.latitude, tenth_microdegree);
    if (std::isfinite(position.confidence.semi_major.value())
        && std::isfinite(position.confidence.semi_minor.value()))
    {
        if ((position.confidence.semi_major.value() * 100 < ASN1_PREFIXED(SemiAxisLength_outOfRange))
            && (position.confidence.semi_minor.value() * 100 < ASN1_PREFIXED(SemiAxisLength_outOfRange))
            && (position.confidence.orientation.value() * 10 < ASN1_PREFIXED(HeadingValue_unavailable)))
        {
            reference_position.positionConfidenceEllipse.semiMajorConfidence = position.confidence.semi_major.value() * 100;    // Value in centimeters
            reference_position.positionConfidenceEllipse.semiMinorConfidence = position.confidence.semi_minor.value() * 100;
            reference_position.positionConfidenceEllipse.semiMajorOrientation = (position.confidence.orientation.value()) * 10; // Value from 0 to 3600
        }
        else
        {
            reference_position.positionConfidenceEllipse.semiMajorConfidence = ASN1_PREFIXED(SemiAxisLength_outOfRange);
            reference_position.positionConfidenceEllipse.semiMinorConfidence = ASN1_PREFIXED(SemiAxisLength_outOfRange);
            reference_position.positionConfidenceEllipse.semiMajorOrientation = ASN1_PREFIXED(HeadingValue_unavailable);
        }
    }
    else
    {
        reference_position.positionConfidenceEllipse.semiMajorConfidence = ASN1_PREFIXED(SemiAxisLength_unavailable);
        reference_position.positionConfidenceEllipse.semiMinorConfidence = ASN1_PREFIXED(SemiAxisLength_unavailable);
        reference_position.positionConfidenceEllipse.semiMajorOrientation = ASN1_PREFIXED(HeadingValue_unavailable);
    }
    if (position.altitude) {
        reference_position.altitude.altitudeValue = to_altitude_value(position.altitude->value());
        reference_position.altitude.altitudeConfidence = to_altitude_confidence(position.altitude->confidence());
    } else {
        reference_position.altitude.altitudeValue = ASN1_PREFIXED(AltitudeValue_unavailable);
        reference_position.altitude.altitudeConfidence = ASN1_PREFIXED(AltitudeConfidence_unavailable);
    }
}

} // namespace facilities
} // namespace vanetza
