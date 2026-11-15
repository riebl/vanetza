#pragma once
#include <vanetza/security/security_module.hpp>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace vanetza
{
namespace security
{

class CredentialStorage;

/**
 * Names of the built-in implementations, e.g. parameters of tests covering every implementation
 *
 * The lists are independent of the library's factories, i.e. tests fail if an implementation is not registered.
 */
std::vector<std::string> builtin_crypto_provider_names();
std::vector<std::string> builtin_security_module_names();

/**
 * Names of the built-in security modules holding their signing keys in software
 */
std::vector<std::string> software_security_module_names();

/**
 * Create a software security module with credential storage
 * \param name one of software_security_module_names()
 * \param storage credential storage, nullptr for a module without storage
 * \return module or nullptr if not built in
 */
std::unique_ptr<SecurityModule> create_software_security_module(
    const std::string& name, std::shared_ptr<CredentialStorage> storage);

/**
 * Test name of an implementation, it consists of alphanumerics only, e.g. Crypto++ is named CryptoPP
 */
std::string implementation_test_name(const ::testing::TestParamInfo<std::string>& info);

} // namespace security
} // namespace vanetza
