#ifndef UPPERTESTER_TRIGGER_HPP
#define UPPERTESTER_TRIGGER_HPP

#include <vanetza/common/byte_buffer.hpp>

class Socket;
class UpperTester;

struct Trigger
{
    uint8_t message_type;

    virtual bool deserialize(const vanetza::ByteBuffer& buffer) = 0;

    virtual void process(UpperTester& tester, Socket& socket) = 0;
};

uint16_t deserialize_uint16_t(const vanetza::ByteBuffer& buffer, int position);

uint32_t deserialize_uint32_t(const vanetza::ByteBuffer& buffer, int position);

#endif /* UPPERTESTER_TRIGGER_HPP */
