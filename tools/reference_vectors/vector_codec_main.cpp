#include "vector_codec.hpp"

#include <cstddef>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace
{

bool read_file(const std::string& path, vanetza::ByteBuffer& out)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        std::cerr << "cannot open input file: " << path << '\n';
        return false;
    }

    out.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    if (stream.bad()) {
        std::cerr << "error reading input file: " << path << '\n';
        return false;
    }
    return true;
}

bool write_file(const std::string& path, const vanetza::ByteBuffer& data)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        std::cerr << "cannot open output file: " << path << '\n';
        return false;
    }

    if (!data.empty()) {
        stream.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    stream.flush();
    if (!stream) {
        std::cerr << "error writing output file: " << path << '\n';
        return false;
    }
    return true;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 5) {
        std::cerr << "usage: " << argv[0] << " <message> <xer-to-uper|uper-to-xer> <input> <output>\n";
        return 1;
    }

    const std::string message = argv[1];
    const std::string direction = argv[2];
    const std::string input_path = argv[3];
    const std::string output_path = argv[4];

    reference_vectors::Encoding encoding;
    if (direction == "xer-to-uper") {
        encoding = reference_vectors::Encoding::Xer;
    } else if (direction == "uper-to-xer") {
        encoding = reference_vectors::Encoding::Uper;
    } else {
        std::cerr << "unknown direction: " << direction << '\n';
        return 1;
    }

    vanetza::ByteBuffer input;
    if (!read_file(input_path, input)) {
        return 1;
    }

    vanetza::ByteBuffer output;
    try {
        output = reference_vectors::transcode(message, encoding, input);
    } catch (const std::exception& e) {
        std::cerr << "transcoding failed: " << e.what() << '\n';
        return 1;
    }

    if (!write_file(output_path, output)) {
        return 1;
    }

    return 0;
}
