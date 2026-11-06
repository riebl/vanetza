#pragma once

#include <vanetza/security/security_module_error.hpp>
#include <system_error>

namespace vanetza
{
namespace security
{

/**
 * Create error code of a failed PSA Crypto API call
 *
 * The native code tells what went wrong inside the PSA implementation,
 * but only the caller knows what the failure means, e.g. an invalid public key given to the operation.
 * \param code PSA status or Mbed TLS error code of the failed call
 * \param condition meaning of the failed operation
 * \return error code with native value equivalent to condition
 */
std::error_code make_psa_error(int code, SecurityModuleError condition) noexcept;

} // namespace security
} // namespace vanetza
