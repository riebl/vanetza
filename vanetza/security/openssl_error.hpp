#pragma once

#include <vanetza/security/security_module_error.hpp>
#include <system_error>

namespace vanetza
{
namespace security
{

/**
 * Take the oldest error from the calling thread's OpenSSL error queue and clear the queue
 *
 * Call it after an OpenSSL operation failed: OpenSSL's error code tells what went wrong inside OpenSSL,
 * but only the caller knows what the failure means, e.g. an invalid public key given to the operation.
 * \param condition meaning of the failed operation
 * \return OpenSSL error code equivalent to condition, errno of a system error in std::system_category(),
 *         or make_error_code(condition) if OpenSSL queued no error
 */
std::error_code take_openssl_error(SecurityModuleError condition) noexcept;

} // namespace security
} // namespace vanetza
