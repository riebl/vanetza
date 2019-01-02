#include "location_table.hpp"
#include <chrono>
#include <limits>

namespace vanetza
{
namespace geonet
{

static_assert(std::numeric_limits<double>::has_quiet_NaN, "quiet NaN value unavailable");

LocationTableEntry::LocationTableEntry(const Runtime& rt) :
    m_runtime(rt), m_is_neighbour(Clock::time_point::min()), m_has_position_vector(false),
    m_pdr(std::numeric_limits<double>::quiet_NaN()), m_pdr_update(rt.now())
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

const MacAddress& LocationTableEntry::link_layer_address() const
{
    return geonet_address().mid();
}

bool LocationTableEntry::is_neighbour() const
{
    return m_is_neighbour > m_runtime.now();
}

void LocationTableEntry::update_pdr(std::size_t packet_size, double beta)
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

bool LocationTableEntry::set_position_vector(const LongPositionVector& pv)
{
    if (is_valid(pv)) {
        m_has_position_vector = true;
        m_position_vector = pv;
        return true;
    } else {
        return false;
    }
}

bool LocationTableEntry::update_position_vector(const LongPositionVector& lpv)
{
    if (has_position_vector()) {
        if (get_position_vector().timestamp < lpv.timestamp) {
            return set_position_vector(lpv);
        }
    } else {
        return set_position_vector(lpv);
    }

    return false;
}

void LocationTableEntry::set_neighbour(bool flag)
{
    m_is_neighbour = flag ? Clock::time_point::max() : Clock::time_point::min();
}

void LocationTableEntry::set_neighbour(bool flag, Clock::duration expiry)
{
    if (flag && expiry > Clock::duration::zero()) {
        m_is_neighbour = m_runtime.now() + expiry;
    } else {
        set_neighbour(flag);
    }
}


LocationTable::LocationTable(const MIB& mib, Runtime& rt) :
    m_table(rt, LocationTableEntryCreator(rt))
{
    m_table.set_lifetime(std::chrono::seconds(mib.itsGnLifetimeLocTE / units::si::seconds));
}

bool LocationTable::has_entry(const Address& addr) const
{
    return m_table.has_value(addr.mid());
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

auto LocationTable::neighbours() const -> neighbour_range
{
    const entry_predicate neighbour_predicate =
        [](const MacAddress&, const LocationTableEntry& entry) {
            return entry.is_neighbour();
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

LocationTableEntry& LocationTable::update(const LongPositionVector& lpv)
{
    LocationTableEntry* entry = m_table.get_value_ptr(lpv.gn_addr.mid());
    if (entry && entry->has_position_vector()) {
        if (entry->update_position_vector(lpv)) {
            m_table.refresh(lpv.gn_addr.mid());
        }
    } else {
        entry = &m_table.refresh(lpv.gn_addr.mid());
        entry->update_position_vector(lpv);
    }
    return *entry;
}

LocationTableEntry& LocationTable::get_or_create_entry(const Address& addr)
{
    return m_table.get_value(addr.mid());
}

LocationTableEntry& LocationTable::get_or_create_entry(const MacAddress& mac)
{
    return m_table.get_value(mac);
}

const LocationTableEntry* LocationTable::get_entry(const Address& addr) const
{
    return m_table.get_value_ptr(addr.mid());
}

const LocationTableEntry* LocationTable::get_entry(const MacAddress& mac) const
{
    return m_table.get_value_ptr(mac);
}

const LongPositionVector* LocationTable::get_position(const Address& addr) const
{
    return get_position(addr.mid());
}

const LongPositionVector* LocationTable::get_position(const MacAddress& mac) const
{
    const LongPositionVector* position = nullptr;
    auto* entry = m_table.get_value_ptr(mac);
    if (entry && entry->has_position_vector()) {
        position = &entry->get_position_vector();
    }
    return position;
}

} // namespace geonet
} // namespace vanetza

