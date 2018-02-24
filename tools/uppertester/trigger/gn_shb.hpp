#ifndef UPPERTESTER_TRIGGER_GN_SHB_HPP
#define UPPERTESTER_TRIGGER_GN_SHB_HPP

#include "trigger.hpp"
#include <cstdint>

// C.5.4 in TR 103 099 V1.3.1
struct ShbTrigger : Trigger
{
    const uint8_t message_type = 0x53;
    // TODO: Implementation

    bool deserialize(const vanetza::ByteBuffer& buffer) override
    {
        // TODO: Implementation

        return true;
    }

    void process(UpperTester& tester, Socket& socket) override;
};

#endif /* UPPERTESTER_TRIGGER_GN_SHB_HPP */
