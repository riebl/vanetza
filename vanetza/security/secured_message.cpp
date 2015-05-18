#include <vanetza/security/secured_message.hpp>

namespace vanetza
{
namespace security
{

void serialize(OutputArchive& ar, const SecuredMessage& message)
{
    ar << message.protocol_version;
    serialize(ar, message.security_profile);
    serialize(ar, message.headerFields);
    serialize(ar, message.payload);
    serialize(ar, message.trailerFields);
}

void deserialize(InputArchive& ar, SecuredMessage& message)
{
    ar >> message.protocol_version;
    deserialize(ar, message.security_profile);
    deserialize(ar, message.headerFields);
    deserialize(ar, message.payload);
    deserialize(ar, message.trailerFields);
}

} // namespace security
} // namespace vanetza
