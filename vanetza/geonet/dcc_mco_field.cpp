#include "dcc_mco_field.hpp"
#include <algorithm>
#include <cmath>

namespace vanetza
{
namespace geonet
{

DccMcoField::DccMcoField() :
    m_cbr_l0_hop(0), m_cbr_l1_hop(0), m_output_power(0)
{
}

DccMcoField::DccMcoField(uint32_t field)
{
    m_cbr_l0_hop = field >> 24;
    m_cbr_l1_hop = field >> 16;
    m_output_power = field >> 11;
}

DccMcoField::operator uint32_t() const
{
    uint32_t field = m_cbr_l0_hop;

    field <<= 8;
    field |= m_cbr_l1_hop;

    field <<= 5;
    field |= m_output_power.raw();

    field <<= 11;
    return field;
}

void DccMcoField::local_cbr(const ChannelLoad& cbr)
{
    m_cbr_l0_hop = std::floor(cbr.value() * 255.0);
}

dcc::ChannelLoad DccMcoField::local_cbr() const
{
    return ChannelLoad(m_cbr_l0_hop / 255.0);
}

void DccMcoField::neighbour_cbr(const ChannelLoad& cbr)
{
    m_cbr_l1_hop = std::floor(cbr.value() * 255.0);
}

dcc::ChannelLoad DccMcoField::neighbour_cbr() const
{
    return ChannelLoad(m_cbr_l1_hop / 255.0);
}

void DccMcoField::output_power(unsigned dbm)
{
    m_output_power = std::min(dbm, 31u);
}

unsigned DccMcoField::output_power() const
{
    return m_output_power.raw();
}

} // namespace geonet
} // namespace vanetza
