#pragma once
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/key_type.hpp>

namespace vanetza
{
namespace security
{

enum class KeyCompression
{
    NoCompression,
    Y0,
    Y1
};

struct PublicKey
{
    ByteBuffer x;
    ByteBuffer y;
    KeyType type;
    KeyCompression compression;
};

} // namespace security
} // namespace vanetza
