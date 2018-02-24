#include "gn.hpp"
#include "gn_geo_broadcast.hpp"
#include "uppertester.hpp"

using namespace vanetza;

void GeoBroadcastTrigger::process(UpperTester& tester, Socket& socket)
{
    GnTriggerResult result;
    result.result = 0;

    // TODO: Implementation

    socket.send(result);
}
