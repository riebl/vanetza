#ifndef UPPERTESTER_TRIGGER_BTP_A_HPP
#define UPPERTESTER_TRIGGER_BTP_A_HPP

#include "trigger.hpp"
#include <cstdint>

// C.7.1 in TR 103 099 V1.3.1
struct BtpATrigger : Trigger
{
    const uint8_t message_type = 0x70;
    uint16_t destination_port;
    uint16_t source_port;

    bool deserialize(const vanetza::ByteBuffer& buffer) override
    {
        if (buffer.size() != 5) {
            return false;
        }

        destination_port = deserialize_uint16_t(buffer, 1);
        source_port = deserialize_uint16_t(buffer, 3);

        return true;
    }

    void process(UpperTester& tester, Socket& socket) override;
};

#endif /* UPPERTESTER_TRIGGER_BTP_A_HPP */
