#ifndef UPPERTESTER_TRIGGER_COMMON_UT_INITIALIZE
#define UPPERTESTER_TRIGGER_COMMON_UT_INITIALIZE

#include "serialization.hpp"
#include "trigger.hpp"
#include <cstdint>
#include <vanetza/security/basic_elements.hpp>

// C.2.1 in TR 103 099 V1.3.1
struct UtInitializeTrigger : public Trigger
{
    static const uint8_t message_type = 0x00;
    vanetza::security::HashedId8 certificate;

    bool deserialize(vanetza::ByteBuffer& buffer)
    {
        if (buffer.size() != 9) {
            return false;
        }

        // TODO assign HashedId8

        return true;
    }
};

struct UtInitializeResult
{
    const uint8_t message_type = 0x01;
    uint8_t result;
};

void serialize(OutputArchive& ar, const UtInitializeResult& result)
{
    ar << result.message_type;
    ar << result.result;
}

#endif /* UPPERTESTER_TRIGGER_COMMON_UT_INITIALIZE */
