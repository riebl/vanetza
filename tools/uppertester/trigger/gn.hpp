#ifndef UPPERTESTER_TRIGGER_GN_HPP
#define UPPERTESTER_TRIGGER_GN_HPP

#include "serialization.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <cstdint>

// C.5.1 + C.5.2 + C.5.3 + C.5.4 + C.5.5 in TR 103 099 V1.3.1
struct GnTriggerResult
{
    const uint8_t message_type = 0x41;
    uint8_t result;
};

void serialize(OutputArchive& ar, const GnTriggerResult& result);

// C.4.6 in TR 103 099 V1.3.1
struct GnEventIndication
{
    const uint8_t message_type = 0x63;
    vanetza::ByteBuffer packet;
};

void serialize(OutputArchive& ar, const GnEventIndication& indication);

#endif /* UPPERTESTER_TRIGGER_GN_HPP */
