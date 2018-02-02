#ifndef ITS_AID_HPP_DOG6R7MT
#define ITS_AID_HPP_DOG6R7MT

#include <vanetza/security/int_x.hpp>

namespace vanetza
{
namespace security
{

/// ITS-AIDs according to TS 102 965
constexpr IntX itsAidCa { 36 };
constexpr IntX itsAidDen { 37 };

/// See http://standards.iso.org/iso/ts/17419/TS17419%20Assigned%20Numbers/
constexpr IntX itsAidGnMgmt { 141 };

} // namespace security
} // namespace vanetza

#endif /* ITS_AID_HPP_DOG6R7MT */
