#include "common_change_position.hpp"

void ChangePositionTrigger::process(UpperTester& tester, Socket& socket)
{
    // TODO: Implement
}

void serialize(OutputArchive& ar, const ChangePositionResult& result)
{
    ar << result.message_type;
    ar << result.result;
}
