#include <vanetza/security/openssl_error.hpp>
#include <vanetza/security/security_module_error.hpp>
#include <gtest/gtest.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <cerrno>
#include <set>
#include <string>
#include <type_traits>

using namespace vanetza::security;

TEST(OpenSslError, oldest_queued_error_is_taken)
{
    ERR_clear_error();
    ERR_raise(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE);
    ERR_raise(ERR_LIB_EC, EC_R_BAD_SIGNATURE);

    const std::error_code error = take_openssl_error(SecurityModuleError::ModuleFailure);
    EXPECT_EQ(ERR_LIB_EC, ERR_GET_LIB(error.value()));
    EXPECT_EQ(EC_R_POINT_IS_NOT_ON_CURVE, ERR_GET_REASON(error.value()));
    const char* reason = ERR_reason_error_string(error.value());
    ASSERT_NE(nullptr, reason);
    EXPECT_NE(std::string::npos, error.message().find(reason));
    EXPECT_EQ(SecurityModuleError::ModuleFailure, error);
    EXPECT_EQ(0u, ERR_peek_error());
}

TEST(OpenSslError, error_has_given_condition)
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
    ERR_clear_error();
    for (SecurityModuleError condition : conditions) {
        SCOPED_TRACE(make_error_code(condition).message());
        ERR_raise(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE);
        const std::error_code error = take_openssl_error(condition);
        EXPECT_EQ(EC_R_POINT_IS_NOT_ON_CURVE, ERR_GET_REASON(error.value()));
        EXPECT_EQ(condition, error);
        category_names.insert(error.category().name());
    }

    // printed error codes tell the condition apart
    EXPECT_EQ(std::extent<decltype(conditions)>::value, category_names.size());
}

// operating system failures are module failures whatever the failed operation means
TEST(OpenSslError, system_error_is_taken_as_errno)
{
    ERR_clear_error();
    ERR_raise(ERR_LIB_SYS, ENOENT);

    const std::error_code error = take_openssl_error(SecurityModuleError::DecryptionFailure);
    EXPECT_EQ(std::error_code(ENOENT, std::system_category()), error);
    EXPECT_EQ(SecurityModuleError::ModuleFailure, error);
}

// OpenSSL queues a system error without errno if a failed system call did not set errno
TEST(OpenSslError, system_error_without_errno_is_module_failure)
{
    ERR_clear_error();
    ERR_raise(ERR_LIB_SYS, 0);
    EXPECT_EQ(make_error_code(SecurityModuleError::ModuleFailure),
        take_openssl_error(SecurityModuleError::DecryptionFailure));
}

TEST(OpenSslError, empty_queue_is_given_condition)
{
    ERR_clear_error();
    EXPECT_EQ(make_error_code(SecurityModuleError::InvalidPublicKey),
        take_openssl_error(SecurityModuleError::InvalidPublicKey));
}
