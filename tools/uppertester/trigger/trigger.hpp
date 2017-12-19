#ifndef UPPERTESTER_TRIGGER
#define UPPERTESTER_TRIGGER

#include <vanetza/common/byte_buffer.hpp>

struct Trigger
{
    uint8_t message_type;
    virtual bool deserialize(vanetza::ByteBuffer& buffer) = 0;
};

uint16_t deserialize_uint16_t(vanetza::ByteBuffer& buffer, int position)
{
    // TODO: Check byte order
    return (buffer.at(position) << 8) + buffer.at(position + 1);
}

uint32_t deserialize_uint32_t(vanetza::ByteBuffer& buffer, int position)
{
    // TODO: Check byte order
    return (buffer.at(position) << 24) + (buffer.at(position + 1) << 16) + (buffer.at(position + 2) << 8) + buffer.at(position + 3);
}

#endif /* UPPERTESTER_TRIGGER */
