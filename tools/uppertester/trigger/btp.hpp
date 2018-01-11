#ifndef UPPERTESTER_TRIGGER_BTP_HPP
#define UPPERTESTER_TRIGGER_BTP_HPP

#include "serialization.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <cstdint>

// C.7.1 + C.7.2 in TR 103 099 V1.3.1
struct BtpTriggerResult
{
    const uint8_t message_type = 0x61;
    uint8_t result;
};

void serialize(OutputArchive& ar, const BtpTriggerResult& result);

// C.7.3 in TR 103 099 V1.3.1
struct BtpEventIndication
{
    const uint8_t message_type = 0x63;
    vanetza::ByteBuffer packet;
};

void serialize(OutputArchive& ar, const BtpEventIndication& indication);

#endif /* UPPERTESTER_TRIGGER_BTP_HPP */
