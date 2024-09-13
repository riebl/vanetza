#pragma once
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/key_type.hpp>
#include <vanetza/security/public_key.hpp>

namespace vanetza
{
namespace security
{

struct PrivateKey
{
    KeyType type;
    ByteBuffer key;
};

} // namespace security
} // namespace vanetza
