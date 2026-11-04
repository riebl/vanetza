#include <vanetza/security/security_module_error.hpp>
#include <gtest/gtest.h>
#include <cerrno>

using vanetza::security::SecurityModuleError;

TEST(SecurityModuleError, system_error_is_module_failure)
{
    const std::error_code error(EIO, std::system_category());
    EXPECT_EQ(SecurityModuleError::ModuleFailure, error);
    EXPECT_NE(SecurityModuleError::KeyNotFound, error);
}

TEST(SecurityModuleError, success_is_no_module_failure)
{
    EXPECT_NE(SecurityModuleError::ModuleFailure, std::error_code());
}
