#pragma once
#include <vanetza/common/byte_buffer.hpp>
#include <array>
#include <cstdint>

namespace vanetza
{
namespace security
{

using HmacKey = std::array<uint8_t, 32>;
using KeyTag = std::array<uint8_t, 16>;

/**
 * \brief generate HMAC key and create HMAC tag on data
 * \param data data to be tagged
 * \param hmacKey generated HMAC key
 * \return tag of data generated with hmacKey
*/
KeyTag create_hmac_tag(const vanetza::ByteBuffer& data, const HmacKey& hmacKey);

} // namespace security
} // namespace vanetza
