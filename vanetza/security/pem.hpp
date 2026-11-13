#pragma once
#include <vanetza/common/byte_buffer.hpp>
#include <boost/optional/optional.hpp>
#include <string>

namespace vanetza
{
namespace security
{

/**
 * Encode data as PEM text according to RFC 7468
 * \param label type of data, e.g. "PUBLIC KEY"
 * \param der DER encoded data
 * \return PEM text with base64 lines of 64 characters
 */
std::string encode_pem(const std::string& label, const ByteBuffer& der);

/**
 * Decode first PEM block of a label according to RFC 7468
 *
 * Text around the block and whitespace within its base64 data are ignored.
 * \param label type of data, e.g. "PUBLIC KEY"
 * \param text PEM text
 * \return DER encoded data, none if there is no block of label or its base64 data is malformed
 */
boost::optional<ByteBuffer> decode_pem(const std::string& label, const std::string& text);

} // namespace security
} // namespace vanetza
