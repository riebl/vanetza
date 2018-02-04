#include "gn.hpp"
#include "gn_geo_anycast.hpp"
#include "uppertester.hpp"

using namespace vanetza;

void GeoAnycastTrigger::process(UpperTester& tester, Socket& socket)
{
    GnTriggerResult result;
    result.result = 0;

    // TODO: Implementation

    socket.send(result);
}
