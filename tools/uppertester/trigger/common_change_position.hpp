#ifndef UPPERTESTER_TRIGGER_COMMON_CHANGE_POSITON_HPP
#define UPPERTESTER_TRIGGER_COMMON_CHANGE_POSITON_HPP

#include "serialization.hpp"
#include "trigger.hpp"
#include <cstdint>

// C.2.2 in TR 103 099 V1.3.1
struct ChangePositionTrigger : Trigger
{
    const static uint8_t message_type = 0x02;
    int32_t delta_latitude;
    int32_t delta_longitude;
    uint8_t delta_elevation;

    bool deserialize(const vanetza::ByteBuffer& buffer) override
    {
        if (buffer.size() != 10) {
            return false;
        }

        delta_latitude = deserialize_uint32_t(buffer, 1);
        delta_longitude = deserialize_uint32_t(buffer, 5);
        delta_elevation = buffer.at(9);

        return true;
    }

    void process(UpperTester& tester, Socket& socket) override;
};

struct ChangePositionResult
{
    const uint8_t message_type = 0x03;
    uint8_t result;
};

void serialize(OutputArchive& ar, const ChangePositionResult& result);

#endif /* UPPERTESTER_TRIGGER_COMMON_CHANGE_POSITON_HPP */
