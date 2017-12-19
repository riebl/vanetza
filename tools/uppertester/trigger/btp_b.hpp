#ifndef UPPERTESTER_TRIGGER_BTP_B
#define UPPERTESTER_TRIGGER_BTP_B

#include "btp.hpp"
#include "trigger.hpp"
#include <cstdint>

// C.7.2 in TR 103 099 V1.3.1
struct BtpBTrigger : Trigger
{
    const uint8_t message_type = 0x71;
    uint16_t destination_port;
    uint16_t destination_port_info;

    bool deserialize(vanetza::ByteBuffer& buffer)
    {
        if (buffer.size() != 5) {
            return false;
        }

        destination_port = deserialize_uint16_t(buffer, 1);
        destination_port_info = deserialize_uint16_t(buffer, 3);

        return true;
    }
};

#endif /* UPPERTESTER_TRIGGER_BTP_B */
