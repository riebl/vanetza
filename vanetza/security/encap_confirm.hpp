#ifndef ENCAP_CONFIRM_HPP
#define ENCAP_CONFIRM_HPP

#include <vanetza/security/secured_message.hpp>
#include <boost/optional.hpp>

namespace vanetza
{
namespace security
{

/** \brief contains output of the signing process
* described in
* TS 102 636-4-1 v1.2.3 (2015-01)
*/
struct EncapConfirm {
    boost::optional<SecuredMessage> sec_packet; // mandatory, but encap may fail
};

} // namespace security
} // namespace vanetza
#endif // ENCAP_CONFIRM_HPP
