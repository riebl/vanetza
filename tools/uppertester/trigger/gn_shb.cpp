#include "gn.hpp"
#include "gn_shb.hpp"
#include "uppertester.hpp"

using namespace vanetza;

void ShbTrigger::process(UpperTester& tester, Socket& socket)
{
    GnTriggerResult result;
    result.result = 0;

    // TODO: Implementation

    socket.send(result);
}
