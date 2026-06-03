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

} // namespace pki
} // namespace vanetza