#ifndef UPPERTESTER_TRIGGER_GN_GEO_ANYCAST_HPP
#define UPPERTESTER_TRIGGER_GN_GEO_ANYCAST_HPP

#include "trigger.hpp"
#include <cstdint>

// C.5.3 in TR 103 099 V1.3.1
struct GeoAnycastTrigger : Trigger
{
    const uint8_t message_type = 0x52;
    // TODO: Implementation

    bool deserialize(const vanetza::ByteBuffer& buffer) override
    {
        // TODO: Implementation

        return true;
    }

    void process(UpperTester& tester, Socket& socket) override;
};

#endif /* UPPERTESTER_TRIGGER_GN_GEO_ANYCAST_HPP */
