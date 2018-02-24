#include "common_ut_initialize.hpp"
#include "uppertester.hpp"

void UtInitializeTrigger::process(UpperTester& tester, Socket& socket)
{
    std::cout << "Processing initialize trigger..." << std::endl;

    tester.reset();

    UtInitializeResult result;
    result.result = 1;

    socket.send(result);
}

void serialize(OutputArchive& ar, const UtInitializeResult& result)
{
    ar << result.message_type;
    ar << result.result;
}
