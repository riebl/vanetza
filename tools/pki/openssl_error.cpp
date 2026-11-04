#include "openssl_error.hpp"
#include <openssl/err.h>
#include <array>
#include <string>

namespace vanetza
{
namespace pki
{
namespace
{

using security::SecurityModuleError;

// OpenSSL's error codes with the meaning of the failed operation, i.e. one category per condition
class OpenSslCategory : public std::error_category
{
public:
    explicit OpenSslCategory(SecurityModuleError condition) : m_condition(condition) {}

    const char* name() const noexcept override
    {
        switch (m_condition) {
            case SecurityModuleError::InvalidKeyReference:
                return "openssl.invalid_key_reference";
            case SecurityModuleError::UnsupportedKeyType:
                return "openssl.unsupported_key_type";
            case SecurityModuleError::ModuleFailure:
                return "openssl.module_failure";
            case SecurityModuleError::KeyNotFound:
                return "openssl.key_not_found";
            case SecurityModuleError::InvalidPublicKey:
                return "openssl.invalid_public_key";
            case SecurityModuleError::DecryptionFailure:
                return "openssl.decryption_failure";
            default:
                return "openssl";
        }
    }

    std::string message(int value) const override
    {
        std::array<char, 256> buffer;
        ERR_error_string_n(value, buffer.data(), buffer.size());
        return buffer.data();
    }

    std::error_condition default_error_condition(int) const noexcept override
    {
        return make_error_condition(m_condition);
    }

private:
    SecurityModuleError m_condition;
};

template<SecurityModuleError Condition> const std::error_category& openssl_category() noexcept
{
    static const OpenSslCategory category { Condition };
    return category;
}

const std::error_category& openssl_category(SecurityModuleError condition) noexcept
{
    switch (condition) {
        case SecurityModuleError::InvalidKeyReference:
            return openssl_category<SecurityModuleError::InvalidKeyReference>();
        case SecurityModuleError::UnsupportedKeyType:
            return openssl_category<SecurityModuleError::UnsupportedKeyType>();
        case SecurityModuleError::ModuleFailure:
            return openssl_category<SecurityModuleError::ModuleFailure>();
        case SecurityModuleError::KeyNotFound:
            return openssl_category<SecurityModuleError::KeyNotFound>();
        case SecurityModuleError::InvalidPublicKey:
            return openssl_category<SecurityModuleError::InvalidPublicKey>();
        case SecurityModuleError::DecryptionFailure:
            return openssl_category<SecurityModuleError::DecryptionFailure>();
        default:
            return openssl_category<SecurityModuleError::ModuleFailure>();
    }
}

} // namespace

std::error_code take_openssl_error(SecurityModuleError condition) noexcept
{
    const unsigned long error = ERR_get_error();
    ERR_clear_error();
    if (error == 0) {
        return make_error_code(condition);
    } else if (ERR_SYSTEM_ERROR(error)) {
        const int errno_value = ERR_GET_REASON(error);
        if (errno_value == 0) {
            // OpenSSL reports a failure without errno, but error code 0 would mean success
            return make_error_code(SecurityModuleError::ModuleFailure);
        } else {
            return std::error_code(errno_value, std::system_category());
        }
    } else {
        // library errors are packed by ERR_PACK, thus never exceed INT_MAX
        return std::error_code(static_cast<int>(error), openssl_category(condition));
    }
}

} // namespace pki
} // namespace vanetza
