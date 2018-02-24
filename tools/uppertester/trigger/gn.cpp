#include "gn.hpp"
#include <vanetza/common/serialization.hpp>

using namespace vanetza;

void serialize(OutputArchive& ar, const GnTriggerResult& result)
{
    ar << result.message_type;
    ar << result.result;
}

void serialize(OutputArchive& ar, const GnEventIndication& indication)
{
    ar << indication.message_type;

    uint16_t size = indication.packet.size();
    serialize(ar, host_cast<uint16_t>(size));

    for (auto byte : indication.packet) {
        ar << byte;
    }
}
