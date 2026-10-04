#include "options.hpp"
#include <iostream>
#include <string>

int main(int argc, const char** argv)
{
    try {
        std::unique_ptr<Case> executable = parse_options(argc, argv);

        if (!executable) {
            return (argc == 2 && std::string(argv[1]) == "--help") ? 0 : 1;
        }

        return executable->execute();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
