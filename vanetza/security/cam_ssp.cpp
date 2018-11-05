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

bool CamPermissions::has(const CamPermissions& required) const
{
    return (m_bits & required.m_bits) == required.m_bits;
}

bool CamPermissions::none() const
{
    return m_bits == 0;
}

std::set<CamPermission> CamPermissions::permissions() const
{
    std::set<CamPermission> perms;

    std::underlying_type<CamPermission>::type bit = 1;
    for (unsigned i = 1; i < sizeof(bit) * 8; ++i) {
        CamPermission permission = static_cast<CamPermission>(bit);
        if (has(permission)) {
            perms.insert(permission);
        }
        bit <<= 1;
    }

    return perms;
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
        case CamPermission::CEN_DSRC_Tolling_Zone:
            result = "CEN DSRC Tolling Zone";
            break;
        case CamPermission::Public_Transport:
            result = "Public Transport";
            break;
        case CamPermission::Special_Transport:
            result = "Special Transport";
            break;
        case CamPermission::Dangerous_Goods:
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
        case CamPermission::Safety_Car:
            // everybody should have an AMG GT S Safety Car ;-)
            result = "Safety Car";
            break;
        case CamPermission::Closed_Lanes:
            result = "Closed Lanes";
            break;
        case CamPermission::Request_For_Right_Of_Way:
            result = "Request for Right of Way";
            break;
        case CamPermission::Request_For_Free_Crossing_At_Traffic_Light:
            result = "Request for Free Crossing at Traffic Light";
            break;
        case CamPermission::No_Passing:
            result = "No Passing";
            break;
        case CamPermission::No_Passing_For_Trucks:
            result = "No Passing for Trucks";
            break;
        case CamPermission::Speed_Limit:
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
