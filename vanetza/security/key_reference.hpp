#pragma once

#include <vanetza/common/byte_buffer.hpp>

namespace vanetza
{
namespace security
{

/**
 * Reference to a private key held by a SecurityModule
 *
 * Only the issuing module can interpret a reference, e.g. as key identifier or wrapped key blob.
 * Applications store references next to their certificates to use the private keys again later.
 */
struct KeyReference
{
    ByteBuffer data;
};

} // namespace security
} // namespace vanetza
