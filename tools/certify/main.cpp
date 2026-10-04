#include "options.hpp"
#include <iostream>
#include <string>

int main(int argc, const char** argv)
{
    try {
        std::unique_ptr<Command> command = parse_options(argc, argv);

        if (!command) {
            return (argc == 2 && std::string(argv[1]) == "--help") ? 0 : 1;
        }

        return command->execute();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
