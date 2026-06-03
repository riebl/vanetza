#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <cstdint>
#include <string>

namespace vanetza
{
namespace pki
{

struct PsidSsp
{
    std::uintmax_t psid;
    ByteBuffer ssp;
};

bool lexical_cast(const std::string&, PsidSsp&);

} // namespace pki
} // namespace vanetza
