#ifndef WEB_VALIDATOR_HPP_UENVJNSAEISNF
#define WEB_VALIDATOR_HPP_UENVJNSAEISNF

#include <vanetza/common/byte_buffer.hpp>
#include <sstream>

// WebValidator refers to https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/

namespace vanetza
{
namespace security
{

void stream_from_string(std::stringstream&, const char*);
void byteBuffer_from_string(ByteBuffer&, const char*);

} // namespace security
} // namespace vanetza

#endif /* WEB_VALIDATOR_HPP_UENVJNSAEISNF */
