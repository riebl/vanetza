#ifndef HEADER_VARIANT_HPP
#define HEADER_VARIANT_HPP

#include <vanetza/geonet/serialization.hpp>
#include <vanetza/geonet/beacon_header.hpp>
#include <vanetza/geonet/gbc_header.hpp>
#include <vanetza/geonet/shb_header.hpp>
#include <boost/variant/variant.hpp>

namespace vanetza
{
namespace geonet
{

typedef boost::variant<BeaconHeader, GeoBroadcastHeader, ShbHeader> HeaderVariant;

/** \brief serialize the underlying header type to an OutputArchive
 *
 * \param header the header to serialize
 * \param ar the archive to write to
 *
 */
void serialize(const HeaderVariant& header, OutputArchive& ar);

/** \brief get the length of the underlying header type
 *
 * \param header the header to get the length from
 * \return std::size_t
 *
 */
std::size_t get_length(const HeaderVariant& header);

} // namespace geonet
} // namespace vanetza

#endif // HEADER_VARIANT_HPP
