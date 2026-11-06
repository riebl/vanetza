#include <vanetza/security/psa_error.hpp>
#include <vanetza/security/security_module_error.hpp>
#include <gtest/gtest.h>
#include <psa/crypto.h>
#include <set>
#include <string>
#include <type_traits>

using namespace vanetza::security;

TEST(PsaError, error_has_given_condition)
{
    const SecurityModuleError conditions[] = {
        SecurityModuleError::InvalidKeyReference,
        SecurityModuleError::UnsupportedKeyType,
        SecurityModuleError::ModuleFailure,
        SecurityModuleError::KeyNotFound,
        SecurityModuleError::InvalidPublicKey,
        SecurityModuleError::DecryptionFailure,
    };

    std::set<std::string> category_names;
    for (SecurityModuleError condition : conditions) {
        SCOPED_TRACE(make_error_code(condition).message());
        const std::error_code error = make_psa_error(PSA_ERROR_INVALID_SIGNATURE, condition);
        EXPECT_EQ(PSA_ERROR_INVALID_SIGNATURE, error.value());
        EXPECT_EQ(condition, error);
        category_names.insert(error.category().name());
    }

    // printed error codes tell the condition apart
    EXPECT_EQ(std::extent<decltype(conditions)>::value, category_names.size());
}
