#include "router_fuzzing_context.hpp"
#include <iostream>
#include <fstream>

vanetza::ByteBuffer readFileIntoBuffer(const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return {};
    }

    const std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    vanetza::ByteBuffer buffer(size);
    if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
        std::cerr << "Error reading file: " << filename << std::endl;
        return {};
    }

    return buffer;
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <filepath>" << std::endl;
        return 1;
    }

    const std::string filename = argv[1];
    vanetza::ByteBuffer buffer = readFileIntoBuffer(filename);

    if (buffer.empty()) {
        return 1;
    }

    vanetza::RouterFuzzingContext context;
    context.indicate(std::move(buffer));
    return 0;
}
