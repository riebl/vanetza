#include "utils.hpp"
#include <cstdint>
#include <stdexcept>
#include <sstream>

void permission_string_to_buffer(const std::string& in, vanetza::ByteBuffer& out)
{
    if (out.empty()) {
        throw std::invalid_argument("SSP buffer lacks version byte.");
    }

    const std::size_t expected_bits = (out.size() - 1 /* version */) * 8;
    if (in.size() != expected_bits) {
        std::stringstream ss;
        ss << "Size mismatch, expected " << (out.size() - 1) << " bytes encoded with one bit per byte.";
        throw std::runtime_error(ss.str());
    }

    uint8_t byte = 0;
    int index = 0;

    for (auto it = in.begin(); it < in.end(); ++it) {
        byte <<= 1;

        if (*it == '0') {
            byte &= 0xFE; // clear last bit
        } else if (*it == '1') {
            byte |= 1; // set last bit
        } else {
            throw std::runtime_error("Unexpected character in permissions, expected only '0' and '1'.");
        }

        if ((index + 1) % 8 == 0) {
            out.at(1 /* version */ + (index / 8)) = byte;
            byte = 0;
        }

        ++index;
    }
}
