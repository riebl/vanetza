#include "address.hpp"

namespace vanetza
{
namespace geonet
{

Address::Address() :
    m_manually_configured(false),
    m_station_type(StationType::UNKNOWN),
    m_country_code(0)
{
}

Address::Address(const MacAddress& addr) :
    m_manually_configured(false),
    m_station_type(StationType::UNKNOWN),
    m_country_code(0),
    m_mid(addr)
{
}

bool Address::operator==(const Address& other) const
{
    return (this->m_manually_configured == other.m_manually_configured &&
        this->m_station_type == other.m_station_type &&
        this->m_country_code == other.m_country_code &&
        this->m_mid == other.m_mid);
}

bool Address::operator!=(const Address& other) const
{
    return !(*this == other);
}

} // namespace geonet
} // namespace vanetza

