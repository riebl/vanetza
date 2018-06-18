#include "location_table.hpp"
#include <chrono>
#include <limits>

namespace vanetza
{
namespace geonet
{

static_assert(std::numeric_limits<double>::has_quiet_NaN, "quiet NaN value unavailable");

LinkInfoEntry::LinkInfoEntry(const Runtime& rt) :
    m_runtime(rt),
    m_pdr(std::numeric_limits<double>::quiet_NaN()), m_pdr_update(rt.now())
{
}

void LinkInfoEntry::update_pdr(std::size_t packet_size, double beta)
{
    using namespace vanetza::units;

    if (std::isnan(m_pdr)) {
        m_pdr = 0.0;
        m_pdr_update = m_runtime.now();
    } else if (beta > 0.0 && beta < 1.0) {
        const std::chrono::duration<double> time_period = m_runtime.now() - m_pdr_update;
        if (time_period.count() > 0.0) {
            double instant_pdr = packet_size / time_period.count();
            m_pdr *= beta;
            m_pdr += (1.0 - beta) * instant_pdr;
            m_pdr_update = m_runtime.now();
        }
    }
}

LocationTableEntry::LocationTableEntry(const Runtime& rt) :
    m_runtime(rt), m_is_neighbour(false), m_has_position_vector(false),
    m_link_info(rt, LinkInfoEntryCreator(rt))
{
}

StationType LocationTableEntry::station_type() const
{
    return geonet_address().station_type();
}

const Address& LocationTableEntry::geonet_address() const
{
    return m_position_vector.gn_addr;
}

const MacAddress& LocationTableEntry::link_layer_address(Channel channel) const
{
    auto link_info = m_link_info.get_value_ptr(channel);
    return link_info->link_layer_address();
}

bool LocationTableEntry::has_channel(Channel channel) const
{
    return m_link_info.has_value(channel);
}

double LocationTableEntry::get_pdr(Channel channel) const
{
    auto link_info = m_link_info.get_value_ptr(channel);
    return link_info->get_pdr();
}

void LocationTableEntry::update_pdr(Channel channel, std::size_t packet_size, double beta)
{
    LinkInfoEntry& link_info = m_link_info.get_value(channel);
    link_info.update_pdr(packet_size, beta);
}

void LocationTableEntry::set_position_vector(const LongPositionVector& pv)
{
    m_has_position_vector = true;
    m_position_vector = pv;
}

void LocationTableEntry::add_link(const Channel channel, const MacAddress& mac)
{
    m_link_info.drop_expired();
    LinkInfoEntry& link_info = m_link_info.get_value(channel);
    link_info.set_link_layer_address(mac);
    link_info.set_channel(channel);
}

bool LocationTableEntry::update_position_vector(const LongPositionVector& lpv)
{
    if (has_position_vector()) {
        if (get_position_vector().timestamp < lpv.timestamp) {
            set_position_vector(lpv);
            return true;
        }
    } else {
        set_position_vector(lpv);
        return true;
    }

    return false;
}

void LocationTableEntry::set_neighbour(bool flag)
{
    m_is_neighbour = flag;
}


LocationTable::LocationTable(const MIB& mib, Runtime& rt) :
    m_table(rt, LocationTableEntryCreator(rt)),
    m_link_table(rt)
{
    m_table.set_lifetime(std::chrono::seconds(mib.itsGnLifetimeLocTE / units::si::seconds));
}

bool LocationTable::has_entry(const Address& addr) const
{
    return m_table.has_value(addr);
}

bool LocationTable::has_neighbours() const
{
    bool found_neighbour = false;
    for (const auto& entry : m_table.map()) {
        if (entry.second.is_neighbour()) {
            found_neighbour = true;
            break;
        }
    }
    return found_neighbour;
}

bool LocationTable::has_neighbours(Channel channel) const
{
    bool found_neighbour = false;
    for (const auto& entry : m_table.map()) {
        if (entry.second.is_neighbour()) {
            if (entry.second.has_channel(channel)) {
                found_neighbour = true;
                break;
            }
        }
    }
    return found_neighbour;
}

auto LocationTable::neighbours() const -> neighbour_range
{
    const entry_predicate neighbour_predicate =
        [](const Address&, const LocationTableEntry& entry) {
            return entry.is_neighbour();
        };
    return filter(neighbour_predicate);
}

auto LocationTable::neighbours(Channel channel) const -> neighbour_range
{
    const entry_predicate neighbour_predicate =
        [channel](const Address&, const LocationTableEntry& entry) {
            return entry.has_channel(channel);
        };
    return filter(neighbour_predicate);
}

auto LocationTable::filter(const entry_predicate& predicate) const -> entry_range
{
    using namespace boost::adaptors;
    std::function<bool(const typename table_type::value_type&)> filter_fn =
        [predicate](const typename table_type::value_type& v) {
            return predicate(v.first, v.second);
        };
    return m_table.map() | filtered(filter_fn) | map_values;
}

void LocationTable::visit(const entry_visitor& visitor) const
{
    for (const auto& entry : m_table.map()) {
        visitor(entry.first, entry.second);
    }
}

void LocationTable::drop_expired()
{
    m_link_table.drop_expired();
    m_table.drop_expired();
}

void LocationTable::update(const Channel channel, const MacAddress& mac, const Address& addr)
{
    LocationTableEntry& entry = m_table.get_value(addr);
    entry.add_link(channel, mac);

    LinkTableEntry& link_entry = m_link_table.get_value(mac);
    link_entry.set_geonet_address(addr);
}

LocationTableEntry& LocationTable::update(const LongPositionVector& lpv)
{
    LocationTableEntry* entry = m_table.get_value_ptr(lpv.gn_addr);
    if (entry && entry->has_position_vector()) {
        if (entry->update_position_vector(lpv)) {
            m_table.refresh(lpv.gn_addr);
        }
    } else {
        entry = &m_table.refresh(lpv.gn_addr);
        entry->update_position_vector(lpv);
    }
    return *entry;
}

LocationTableEntry& LocationTable::get_or_create_entry(const Address& addr)
{
    return m_table.get_value(addr);
}

LocationTableEntry& LocationTable::get_or_create_entry(const MacAddress& mac)
{
    auto addr = m_link_table.get_value(mac);
    return m_table.get_value(addr.geonet_address());
}

const LocationTableEntry* LocationTable::get_entry(const Address& addr) const
{
    return m_table.get_value_ptr(addr);
}

const LocationTableEntry* LocationTable::get_entry(const MacAddress& mac) const
{
    auto addr = m_link_table.get_value_ptr(mac);
    return m_table.get_value_ptr(addr->geonet_address());
}

const LongPositionVector* LocationTable::get_position(const Address& addr) const
{
    const LongPositionVector* position = nullptr;
    auto* entry = m_table.get_value_ptr(addr);
    if (entry && entry->has_position_vector()) {
        position = &entry->get_position_vector();
    }
    return position;
}

const LongPositionVector* LocationTable::get_position(const MacAddress& mac) const
{
    auto addr = m_link_table.get_value_ptr(mac);
    return get_position(addr->geonet_address());
}

} // namespace geonet
} // namespace vanetza

