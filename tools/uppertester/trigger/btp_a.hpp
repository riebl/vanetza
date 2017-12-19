#ifndef UPPERTESTER_TRIGGER_BTP_A
#define UPPERTESTER_TRIGGER_BTP_A

#include "btp.hpp"
#include "trigger.hpp"
#include <cstdint>

// C.7.1 in TR 103 099 V1.3.1
struct BtpATrigger : Trigger
{
    const uint8_t message_type = 0x70;
    uint16_t destination_port;
    uint16_t source_port;

    bool deserialize(vanetza::ByteBuffer& buffer)
    {
        if (buffer.size() != 5) {
            return false;
        }

        destination_port = deserialize_uint16_t(buffer, 1);
        source_port = deserialize_uint16_t(buffer, 3);

        return true;
    }
};

#endif /* UPPERTESTER_TRIGGER_BTP_A */
