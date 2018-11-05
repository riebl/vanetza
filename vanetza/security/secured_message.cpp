#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/byte_buffer_sink.hpp>
#include <vanetza/security/exception.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/serialization.hpp>
#include <boost/iostreams/stream.hpp>

namespace vanetza
{
namespace security
{

HeaderField* SecuredMessage::header_field(HeaderFieldType type)
{
    HeaderField* match = nullptr;
    for (auto& field : header_fields) {
        if (get_type(field) == type) {
            match = &field;
            break;
        }
    }
    return match;
}

const HeaderField* SecuredMessage::header_field(HeaderFieldType type) const
{
    const HeaderField* match = nullptr;
    for (auto& field : header_fields) {
        if (get_type(field) == type) {
            match = &field;
            break;
        }
    }
    return match;
}

TrailerField* SecuredMessage::trailer_field(TrailerFieldType type)
{
    TrailerField* match = nullptr;
    for (auto& field : trailer_fields) {
        if (get_type(field) == type) {
            match = &field;
            break;
        }
    }
    return match;
}

const TrailerField* SecuredMessage::trailer_field(TrailerFieldType type) const
{
    const TrailerField* match = nullptr;
    for (auto& field : trailer_fields) {
        if (get_type(field) == type) {
            match = &field;
            break;
        }
    }
    return match;
}

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

size_t deserialize(InputArchive& ar, SecuredMessage& message)
{
    uint8_t protocol_version = 0;
    ar >> protocol_version;
    size_t length = sizeof(protocol_version);
    if (protocol_version == 2) {
        const size_t hdr_length = deserialize(ar, message.header_fields);
        length += hdr_length + length_coding_size(hdr_length);
        length += deserialize(ar, message.payload);
        const size_t trlr_length = deserialize(ar, message.trailer_fields);
        length += trlr_length + length_coding_size(trlr_length);
    } else {
        throw deserialization_error("Unsupported SecuredMessage protocol version");
    }
    return length;
}

ByteBuffer convert_for_signing(const SecuredMessage& message, const std::list<TrailerField>& trailer_fields)
{
    ByteBuffer buf;
    byte_buffer_sink sink(buf);

    boost::iostreams::stream_buffer<byte_buffer_sink> stream(sink);
    OutputArchive ar(stream);

    const uint8_t protocol_version = message.protocol_version();
    ar << protocol_version;
    serialize(ar, message.header_fields);
    serialize(ar, message.payload);

    // Encode the total length, all trailer fields before the signature and the type of the signature
    // (see TS 103 097 v1.2.1, section 5.6)
    serialize_length(ar, get_size(trailer_fields));
    for (auto& elem : trailer_fields) {
        TrailerFieldType type = get_type(elem);
        if (type == TrailerFieldType::Signature) {
            serialize(ar, type);
            break; // exclude fields after signature
        } else {
            serialize(ar, elem);
        }
    }

    stream.close();
    return buf;
}

} // namespace security
} // namespace vanetza
