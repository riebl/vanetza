#include "gn.hpp"
#include "gn_geo_unicast.hpp"
#include "uppertester.hpp"

using namespace vanetza;

void GeoUnicastTrigger::process(UpperTester& tester, Socket& socket)
{
    GnTriggerResult result;
    result.result = 0;

    // TODO: Implementation

    socket.send(result);
}
