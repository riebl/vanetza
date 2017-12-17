#ifndef LINK_LAYER_HPP_F2JBRUTL
#define LINK_LAYER_HPP_F2JBRUTL

#include <vanetza/net/mac_address.hpp>

namespace vanetza
{
namespace geonet
{

struct LinkLayer
{
    MacAddress sender;
    MacAddress destination;
};

} // namespace geonet
} // namespace vanetza

#endif /* LINK_LAYER_HPP_F2JBRUTL */

