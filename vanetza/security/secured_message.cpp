#include <vanetza/security/secured_message.hpp>

namespace vanetza
{
namespace security
{

size_t get_size(const SecuredMessage& message)
{
    size_t size = sizeof(message.protocol_version);
    size += sizeof(message.security_profile);
    size += get_size(message.header_fields);
    size += length_coding_size(get_size(message.header_fields));
    size += get_size(message.trailer_fields);
    size += length_coding_size(get_size(message.trailer_fields));
    size += get_size(message.payload);
    size += length_coding_size(get_size(message.payload));
    return size;
}

void serialize(OutputArchive& ar, const SecuredMessage& message)
{
    ar << message.protocol_version;
    serialize(ar, message.security_profile);
    serialize(ar, message.header_fields);
    serialize(ar, message.payload);
    serialize(ar, message.trailer_fields);
}

void deserialize(InputArchive& ar, SecuredMessage& message)
{
    ar >> message.protocol_version;
    deserialize(ar, message.security_profile);
    deserialize(ar, message.header_fields);
    deserialize(ar, message.payload);
    deserialize(ar, message.trailer_fields);
}

} // namespace security
} // namespace vanetza
