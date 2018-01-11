#include "trigger.hpp"

uint16_t deserialize_uint16_t(const vanetza::ByteBuffer& buffer, int position)
{
    return (buffer.at(position) << 8) + buffer.at(position + 1);
}

uint32_t deserialize_uint32_t(const vanetza::ByteBuffer& buffer, int position)
{
    return (buffer.at(position) << 24) + (buffer.at(position + 1) << 16) + (buffer.at(position + 2) << 8) + buffer.at(position + 3);
}
