#ifndef SERIALZATION_HPP_IENSIAL4
#define SERIALZATION_HPP_IENSIAL4

#include <vanetza/geonet/serialization.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

namespace vanetza{
namespace security{

typedef boost::archive::binary_iarchive InputArchive;
typedef boost::archive::binary_oarchive OutputArchive;

} // namespace security
} // namespace vanetza

#endif /* SERIALZATION_HPP_IENSIAL4 */
