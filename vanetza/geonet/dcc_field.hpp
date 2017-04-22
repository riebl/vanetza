#ifndef DCC_FIELD_HPP_EPTBYHAU
#define DCC_FIELD_HPP_EPTBYHAU

#include <vanetza/geonet/dcc_mco_field.hpp>
#include <vanetza/geonet/serialization.hpp>
#include <boost/optional/optional.hpp>
#include <boost/variant/variant.hpp>
#include <cstdint>

namespace vanetza
{
namespace geonet
{

/**
 * DccField represents the supported variants for the DCC field in SHB headers.
 *
 * \note Enclosed types are using "host byte order".
 *       Byte order conversion is handled by serialize and deserialize functions.
 */
using DccField = boost::variant<DccMcoField, uint32_t>;

boost::optional<DccMcoField> get_dcc_mco(const DccField&);

void serialize(const DccField&, OutputArchive&);
void deserialize(DccField&, InputArchive&);

} // namespace geonet
} // namespace vanetza

#endif /* DCC_FIELD_HPP_EPTBYHAU */

