#ifndef UPPERTESTER_TRIGGER_COMMON_UT_RESULT
#define UPPERTESTER_TRIGGER_COMMON_UT_RESULT

#include "serialization.hpp"
#include <cstdint>

// C.1 in TR 103 099 V1.3.1
struct UtResult
{
    const uint8_t message_type = 0x01;
    uint8_t result;
};

void serialize(OutputArchive& ar, const UtResult& result)
{
    ar << result.message_type;
    ar << result.result;
}

#endif /* UPPERTESTER_TRIGGER_COMMON_UT_RESULT */
