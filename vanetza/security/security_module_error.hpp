#pragma once

#include <system_error>
#include <type_traits>

namespace vanetza
{
namespace security
{

/**
 * Generic error conditions of SecurityModule operations
 *
 * Modules without native error codes report these directly via make_error_code().
 * Modules with native error codes map them to these conditions by their own error category.
 */
enum class SecurityModuleError
{
    InvalidKeyReference = 1, // module cannot interpret the key reference
    UnsupportedKeyType, // module does not support the requested curve
    ModuleFailure, // module malfunctioned, e.g. a failed OpenSSL or hardware call
    KeyNotFound // module has no key stored for the given public key
};

const std::error_category& security_module_category() noexcept;
std::error_condition make_error_condition(SecurityModuleError) noexcept;
std::error_code make_error_code(SecurityModuleError) noexcept;

} // namespace security
} // namespace vanetza

namespace std
{

template<>
struct is_error_condition_enum<vanetza::security::SecurityModuleError> : true_type {};

} // namespace std
