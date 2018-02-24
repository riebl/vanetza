#include "common_change_pseudonym.hpp"

void ChangePseudonymTrigger::process(UpperTester& tester, Socket& socket)
{
    // TODO: Implement
}

void serialize(OutputArchive& ar, const ChangePseudonymResult& result)
{
    ar << result.message_type;
    ar << result.result;
}
