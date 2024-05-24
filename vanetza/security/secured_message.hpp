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

class SecuredMessageView
{
public:
    explicit SecuredMessageView(const SecuredMessage& msg);

    template<typename Visitor>
    typename Visitor::result_type apply_visitor(Visitor& visitor) const
    {
        return m_variant.apply_visitor(visitor);
    }

private:
    boost::variant<const v2::SecuredMessage&, const v3::SecuredMessage&> m_variant;
};

ItsAid get_its_aid(const SecuredMessage&);
ItsAid get_its_aid(const SecuredMessageView&);

std::size_t get_size(const SecuredMessage& msg);
std::size_t get_size(const SecuredMessageView& msg);

void serialize(OutputArchive& ar, const SecuredMessage& msg);
void serialize(OutputArchive& ar, const SecuredMessageView& msg);

std::size_t deserialize(InputArchive& ar, SecuredMessage&);

PacketVariant get_payload_copy(const SecuredMessage&);
PacketVariant get_payload_copy(const SecuredMessageView&);

} // namespace security
} // namespace vanetza

#endif /* BAAED6CC_75E1_4851_B84B_7B90FD87FBAC */