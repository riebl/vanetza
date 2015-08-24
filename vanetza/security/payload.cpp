#include <vanetza/security/payload.hpp>
#include <vanetza/security/deserialization_error.hpp>
#include <vanetza/security/length_coding.hpp>

namespace vanetza
{
namespace security
{



size_t get_size(const Payload& payload)
{
    size_t size = sizeof(PayloadType);
    size += payload.buffer.size();
    size += length_coding_size(payload.buffer.size());
    return size;
}

size_t get_size(const ByteBuffer& buf)
{
    size_t size = buf.size();
    size += length_coding_size(size);
    return size;
}

void serialize(OutputArchive& ar, const Payload& payload)
{
    serialize(ar, payload.type);
    size_t size = payload.buffer.size();
    serialize_length(ar, size);
    for (auto& elem : payload.buffer) {
        ar << elem;
    }
}


size_t deserialize(InputArchive& ar, ByteBuffer& buf)
{
    size_t size = deserialize_length(ar);
    size_t ret_size = size;
    ret_size += length_coding_size(size);
    for (size_t c = 0; c < size; c++) {
        uint8_t elem;
        ar >> elem;
        buf.push_back(elem);
    }
    return ret_size;
}

size_t deserialize(InputArchive& ar, Payload& payload)
{
    size_t size = sizeof(PayloadType);
    PayloadType type;
    deserialize(ar, type);
    payload.type = type;
    ByteBuffer buf;
    size += deserialize(ar, buf);
    payload.buffer = buf;

    return size;
}

} // namespace security
} // namespace vanetza

