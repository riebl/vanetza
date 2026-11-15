#ifndef CERTIFY_UTILS_HPP
#define CERTIFY_UTILS_HPP

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/security_module.hpp>
#include <memory>
#include <string>

void permission_string_to_buffer(const std::string&, vanetza::ByteBuffer&);

/**
 * Names of built-in security modules including the default, e.g. for help texts
 */
std::string security_module_names();

/**
 * Create a built-in security module
 * \param name name of module or "default"
 * \return module, std::runtime_error is thrown if it is not built in
 */
std::unique_ptr<vanetza::security::SecurityModule> create_security_module_or_throw(const std::string& name);

#endif /* CERTIFY_UTILS_HPP */
