#pragma once

#include "vanetza/common/byte_buffer.hpp"
#include <array>
#include <cstdint>
#include <string>

namespace vanetza
{

namespace pki
{

std::string hexstring(const std::uint8_t* buf, std::size_t len);
std::string hexstring(const std::string& input);
std::string hexstring(const ByteBuffer& buffer);

template<size_t N> std::string hexstring(const std::array<std::uint8_t, N>& array)
{
    return hexstring(array.data(), array.size());
}

// true iff input is a non-empty, even-length run of hex digits
bool is_valid_hexstring(const std::string& input);

// decode hex digits to raw bytes
std::string parse_hexstring(const std::string& input);

} // namespace pki
} // namespace vanetza