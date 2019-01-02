#ifndef LOCATION_TABLE_HPP_EMPVZSHQ
#define LOCATION_TABLE_HPP_EMPVZSHQ

#include <vanetza/common/object_container.hpp>
#include <vanetza/geonet/address.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/position_vector.hpp>
#include <vanetza/geonet/soft_state_map.hpp>
#include <vanetza/geonet/station_type.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/map.hpp>

namespace vanetza
{
namespace geonet
{

class LocationTableEntry
{
public:
    LocationTableEntry(const Runtime& rt);

    const Address& geonet_address() const;
    const MacAddress& link_layer_address() const;
    StationType station_type() const;

    /**
     * Get packed data rate (PDR) of corresponding source.
     * \return PDR in bytes per second, might be not-a-number
     */
    double get_pdr() const { return m_pdr; }

    /**
     * Update packet data rate.
     * See Annex B of EN 302 636-4-1 for details.
     * \param packet_size received number of bytes
     * \param beta weight factor for exponential moving average ]0; 1[
     */
    void update_pdr(std::size_t packet_size, double beta = 0.5);

    /**
     * Check if position vector has been set before
     * \return  false after entry initialization
     *          true after set_position_vector invocations
     */
    bool has_position_vector() const { return m_has_position_vector; }

    /**
     * Get stored position vector
     * \return position vector (empty until set_position_vector invocation)
     */
    const LongPositionVector& get_position_vector() const { return m_position_vector; }

    /**
     * Update stored position vector (only after time stamp check)
     * \param pv source position vector
     * \return true if position vector passed time stamp check
     */
    bool update_position_vector(const LongPositionVector& pv);

    /**
     * Check if this entry belongs to a direct neighbour
     * \return true if direct neighbour
     */
    bool is_neighbour() const;

    /**
     * Set neighbour relation
     * \param flag true if entry represents a direct neighbour
     */
    void set_neighbour(bool flag);

    /**
     * Set neighbour relation with expiry
     * \param flag true if entry represents a direct neighbour
     * \param expiry reset neighbour relation to false after expiry
     */
    void set_neighbour(bool flag, Clock::duration expiry);

    ObjectContainer extensions;

private:
    /**
     * Set stored position vector (without timestamp check)
     * \param pv source position vector
     */
    bool set_position_vector(const LongPositionVector& pv);

    const Runtime& m_runtime;
    Clock::time_point m_is_neighbour;
    bool m_has_position_vector;
    LongPositionVector m_position_vector;
    double m_pdr; /*< packet data rate in bytes per second */
    Clock::time_point m_pdr_update;
};

class LocationTableEntryCreator
{
public:
    LocationTableEntryCreator(const Runtime& rt) : m_runtime(rt) {}
    LocationTableEntry operator()() { return LocationTableEntry(m_runtime); }

private:
    const Runtime& m_runtime;
};

/**
 * GeoNetworking LocationTable
 * See section 7.1 of EN 302 636-4-1 for details.
 */
class LocationTable
{
public:
    using table_type = SoftStateMap<MacAddress, LocationTableEntry, LocationTableEntryCreator>;
    using entry_visitor = std::function<void(const MacAddress&, const LocationTableEntry&)>;
    using entry_predicate = std::function<bool(const MacAddress&, const LocationTableEntry&)>;
    using entry_range =
        boost::select_second_const_range<
            boost::filtered_range<
                std::function<bool(const typename table_type::value_type&)>,
                const typename table_type::map_range>>;
    using neighbour_range = entry_range;

    LocationTable(const MIB&, Runtime&);
    bool has_entry(const Address&) const;
    LocationTableEntry& update(const LongPositionVector&);
    LocationTableEntry& get_or_create_entry(const Address&);
    LocationTableEntry& get_or_create_entry(const MacAddress&);
    const LocationTableEntry* get_entry(const Address&) const;
    const LocationTableEntry* get_entry(const MacAddress&) const;
    const LongPositionVector* get_position(const Address&) const;
    const LongPositionVector* get_position(const MacAddress&) const;
    bool has_neighbours() const;
    neighbour_range neighbours() const;
    entry_range filter(const entry_predicate&) const;
    void visit(const entry_visitor&) const;
    void drop_expired() { m_table.drop_expired(); }

private:
    table_type m_table;
};

} // namespace geonet
} // namespace vanetza

#endif /* LOCATION_TABLE_HPP_EMPVZSHQ */

