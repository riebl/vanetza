#include "gn.hpp"
#include "gn_tsb.hpp"
#include "uppertester.hpp"

using namespace vanetza;

void TsbTrigger::process(UpperTester& tester, Socket& socket)
{
    GnTriggerResult result;
    result.result = 0;

    // TODO: Implementation

    socket.send(result);
}
