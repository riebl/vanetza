#include <vanetza/security/cam_ssp.hpp>
#include <boost/format.hpp>

namespace vanetza
{
namespace security
{

CamPermissions::CamPermissions() : m_bits(0)
{
}

CamPermissions::CamPermissions(CamPermission cp) : m_bits(static_cast<value_type>(cp))
{
}

CamPermissions::CamPermissions(const std::initializer_list<CamPermission>& cps) : m_bits(0)
{
    for (CamPermission cp : cps) {
        add(cp);
    }
}

bool CamPermissions::has(CamPermission cp) const
{
    const auto cp_raw = static_cast<value_type>(cp);
    return (m_bits & cp_raw) == cp_raw;
}

bool CamPermissions::has(const std::initializer_list<CamPermission>& cps) const
{
    for (CamPermission cp : cps) {
        if (!has(cp)) return false;
    }
    return true;
}

bool CamPermissions::none() const
{
    return m_bits == 0;
}

CamPermissions& CamPermissions::add(CamPermission cp)
{
    m_bits |= static_cast<value_type>(cp);
    return *this;
}

CamPermissions& CamPermissions::remove(CamPermission cp)
{
    m_bits &= ~static_cast<value_type>(cp);
    return *this;
}

ByteBuffer CamPermissions::encode() const
{
    return ByteBuffer({1, static_cast<uint8_t>(m_bits), static_cast<uint8_t>(m_bits >> 8) });
}

CamPermissions CamPermissions::decode(const ByteBuffer& buffer)
{
    CamPermissions permissions;
    if (buffer.size() == 3 && buffer[0] == 1) {
        permissions.m_bits = buffer[2];
        permissions.m_bits <<= 8;
        permissions.m_bits |= buffer[1];
    }
    return permissions;
}

std::string stringify(CamPermission permission)
{
    std::string result;
    switch (permission) {
        case CamPermission::CenDsrcTollingZone:
            result = "CEN DSRC Tolling Zone";
            break;
        case CamPermission::PublicTransport:
            result = "Public Transport";
            break;
        case CamPermission::SpecialTransport:
            result = "Special Transport";
            break;
        case CamPermission::DangerousGoods:
            result = "Dangerous Goods";
            break;
        case CamPermission::Roadwork:
            result = "Roadwork";
            break;
        case CamPermission::Rescue:
            result = "Rescue";
            break;
        case CamPermission::Emergency:
            result = "Emergency";
            break;
        case CamPermission::SafetyCar:
            // everybody should have an AMG GT S Safety Car ;-)
            result = "Safety Car";
            break;
        case CamPermission::ClosedLanes:
            result = "Closed Lanes";
            break;
        case CamPermission::RequestForRightOfWay:
            result = "Request for Right of Way";
            break;
        case CamPermission::RequestForFreeCrossingAtTrafficLight:
            result = "Request for Free Crossing at Traffic Light";
            break;
        case CamPermission::NoPassing:
            result = "No Passing";
            break;
        case CamPermission::NoPassingForTrucks:
            result = "No Passing for Trucks";
            break;
        case CamPermission::SpeedLimit:
            result = "Speed Limit";
            break;
        default:
            static_assert(sizeof(CamPermission) == 2, "Expected CamPermission to be 2 bytes wide");
            result = str(boost::format("Reserved (%0#6x)") % static_cast<uint16_t>(permission));
            break;
    }
    return result;
}

} // namespace security
} // namespace vanetza
