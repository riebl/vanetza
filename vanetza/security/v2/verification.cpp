#include <vanetza/security/v2/verification.hpp>

namespace vanetza
{
namespace security
{
namespace v2
{

bool check_generation_time(const SecuredMessage& message, Clock::time_point now)
{
    using namespace std::chrono;

    bool valid = false;
    const Time64* generation_time = message.header_field<HeaderFieldType::Generation_Time>();
    if (generation_time) {
        // Values are picked from C2C-CC Basic System Profile v1.1.0, see RS_BSP_168
        static const auto generation_time_future = milliseconds(40);
        static const Clock::duration generation_time_past_default = minutes(10);
        static const Clock::duration generation_time_past_ca = seconds(2);
        auto generation_time_past = generation_time_past_default;

        const IntX* its_aid = message.header_field<HeaderFieldType::Its_Aid>();
        if (its_aid && aid::CA == *its_aid) {
            generation_time_past = generation_time_past_ca;
        }

        if (*generation_time > convert_time64(now + generation_time_future)) {
            valid = false;
        } else if (*generation_time < convert_time64(now - generation_time_past)) {
            valid = false;
        } else {
            valid = true;
        }
    }

    return valid;
}

bool check_generation_location(const SecuredMessage& message, const Certificate& cert)
{
    const IntX* its_aid = message.header_field<HeaderFieldType::Its_Aid>();
    if (its_aid && aid::CA == *its_aid) {
        return true; // no check required for CAMs, field not even allowed
    }

    const ThreeDLocation* generation_location = message.header_field<HeaderFieldType::Generation_Location>();
    if (generation_location) {
        auto region = cert.get_restriction<ValidityRestrictionType::Region>();

        if (!region || get_type(*region) == RegionType::None) {
            return true;
        }

        return is_within(TwoDLocation(*generation_location), *region);
    }

    return false;
}

bool check_certificate_time(const Certificate& certificate, Clock::time_point now)
{
    auto time = certificate.get_restriction<ValidityRestrictionType::Time_Start_And_End>();
    auto time_now = convert_time32(now);

    if (!time) {
        return false; // must be present
    }

    if (time->start_validity > time_now || time->end_validity < time_now) {
        return false; // premature or outdated
    }

    return true;
}

bool check_certificate_region(const Certificate& certificate, const PositionFix& position)
{
    auto region = certificate.get_restriction<ValidityRestrictionType::Region>();

    if (!region || get_type(*region) == RegionType::None) {
        return true;
    }

    if (!position.confidence) {
        return false; // cannot check region restrictions without good position fix
    }

    return is_within(TwoDLocation(position.latitude, position.longitude), *region);
}

} // namespace v2
} // namespace security
} // namespace vanetza
