#include <vanetza/security/exception.hpp>
#include <vanetza/security/secured_message.hpp>

namespace vanetza
{
namespace security
{

size_t get_size(const SecuredMessage& message)
{
    size_t size = sizeof(uint8_t); // protocol version
    size += get_size(message.header_fields);
    size += length_coding_size(get_size(message.header_fields));
    size += get_size(message.trailer_fields);
    size += length_coding_size(get_size(message.trailer_fields));
    size += get_size(message.payload);
    return size;
}

void serialize(OutputArchive& ar, const SecuredMessage& message)
{
    const uint8_t protocol_version = message.protocol_version();
    ar << protocol_version;
    serialize(ar, message.header_fields);
    serialize(ar, message.payload);
    serialize(ar, message.trailer_fields);
}

void deserialize(InputArchive& ar, SecuredMessage& message)
{
    uint8_t protocol_version = 0;
    ar >> protocol_version;
    if (protocol_version == 2) {
        deserialize(ar, message.header_fields);
        deserialize(ar, message.payload);
        deserialize(ar, message.trailer_fields);
    } else {
        throw deserialization_error("Unsupported SecuredMessage protocol version");
    }
}

} // namespace security
} // namespace vanetza
