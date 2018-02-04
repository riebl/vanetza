#include "gn.hpp"

void serialize(OutputArchive& ar, const GnTriggerResult& result)
{
    ar << result.message_type;
    ar << result.result;
}

void serialize(OutputArchive& ar, const GnEventIndication& indication)
{
    ar << indication.message_type;

    uint16_t size = indication.packet.size();

    ar << (uint8_t) ((size >> 8) & 0xFF);
    ar << (uint8_t) ((size >> 0) & 0xFF);

    for (auto byte : indication.packet) {
        ar << byte;
    }
}
