#ifndef UPPERTESTER_TRIGGER_COMMON_CHANGE_PSEUDONYM_HPP
#define UPPERTESTER_TRIGGER_COMMON_CHANGE_PSEUDONYM_HPP

#include "serialization.hpp"
#include "trigger.hpp"
#include <cstdint>

// C.2.3 in TR 103 099 V1.3.1
struct ChangePseudonymTrigger : Trigger
{
    const static uint8_t message_type = 0x04;

    bool deserialize(const vanetza::ByteBuffer& buffer) override
    {
        return buffer.size() == 1;
    }

    void process(UpperTester& tester, Socket& socket) override;
};

struct ChangePseudonymResult
{
    const uint8_t message_type = 0x05;
    uint8_t result;
};

void serialize(OutputArchive& ar, const ChangePseudonymResult& result);

#endif /* UPPERTESTER_TRIGGER_COMMON_CHANGE_PSEUDONYM_HPP */
