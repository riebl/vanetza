#ifndef BAAED6CC_75E1_4851_B84B_7B90FD87FBAC
#define BAAED6CC_75E1_4851_B84B_7B90FD87FBAC

#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/serialization.hpp>
#include <vanetza/net/packet_variant.hpp>
#include <vanetza/security/v2/secured_message.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <boost/variant/variant.hpp>

namespace vanetza
{
namespace security
{

using SecuredMessage = boost::variant<v2::SecuredMessage, v3::SecuredMessage>;

ItsAid get_its_aid(const SecuredMessage&);

std::size_t get_size(const SecuredMessage& msg);

void serialize(OutputArchive& ar, const SecuredMessage& msg);

std::size_t deserialize(InputArchive& ar, SecuredMessage&);

PacketVariant get_payload_copy(const SecuredMessage&);

} // namespace security
} // namespace vanetza

#endif /* BAAED6CC_75E1_4851_B84B_7B90FD87FBAC */