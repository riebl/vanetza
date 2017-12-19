#ifndef UPPERTESTER_TRIGGER_COMMON_CHANGE_PSEUDONYM
#define UPPERTESTER_TRIGGER_COMMON_CHANGE_PSEUDONYM

#include "serialization.hpp"
#include "trigger.hpp"
#include <cstdint>

// C.2.3 in TR 103 099 V1.3.1
struct ChangePseudonymTrigger : Trigger
{
    const static uint8_t message_type = 0x04;

    bool deserialize(vanetza::ByteBuffer& buffer)
    {
        return buffer.size() == 1;
    }
};

struct ChangePseudonymResult
{
    const uint8_t message_type = 0x05;
    uint8_t result;
};

void serialize(OutputArchive& ar, const ChangePseudonymResult& result)
{
    ar << result.message_type;
    ar << result.result;
}

#endif /* UPPERTESTER_TRIGGER_COMMON_CHANGE_PSEUDONYM */
