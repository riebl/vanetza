#include "options.hpp"
#include <boost/program_options.hpp>
#include <iostream>

// using namespace vanetza;

int main(int argc, const char** argv)
{
    try {
        std::unique_ptr<Command> command = parse_options(argc, argv);
        return command->execute();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
