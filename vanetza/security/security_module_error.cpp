#include <vanetza/security/security_module_error.hpp>
#include <string>

namespace vanetza
{
namespace security
{
namespace
{

class SecurityModuleCategory : public std::error_category
{
public:
    const char* name() const noexcept override
    {
        return "vanetza.security_module";
    }

    std::string message(int value) const override
    {
        switch (static_cast<SecurityModuleError>(value)) {
            case SecurityModuleError::InvalidKeyReference:
                return "invalid key reference";
            case SecurityModuleError::UnsupportedKeyType:
                return "unsupported key type";
            case SecurityModuleError::ModuleFailure:
                return "security module failure";
            case SecurityModuleError::KeyNotFound:
                return "key not found";
            case SecurityModuleError::InvalidPublicKey:
                return "invalid public key";
            case SecurityModuleError::DecryptionFailure:
                return "decryption failed";
            case SecurityModuleError::UnsupportedHashAlgorithm:
                return "unsupported hash algorithm";
            case SecurityModuleError::InvalidHashLength:
                return "invalid hash length";
            case SecurityModuleError::InvalidPrivateKey:
                return "invalid private key";
            default:
                return "unknown security module error";
        }
    }

    bool equivalent(const std::error_code& code, int condition) const noexcept override
    {
        // operating system failures within a module are module failures
        if (code && code.category() == std::system_category()) {
            return condition == static_cast<int>(SecurityModuleError::ModuleFailure);
        }
        return std::error_category::equivalent(code, condition);
    }
};

} // namespace

const std::error_category& security_module_category() noexcept
{
    static const SecurityModuleCategory category {};
    return category;
}

std::error_condition make_error_condition(SecurityModuleError error) noexcept
{
    return std::error_condition(static_cast<int>(error), security_module_category());
}

std::error_code make_error_code(SecurityModuleError error) noexcept
{
    return std::error_code(static_cast<int>(error), security_module_category());
}

} // namespace security
} // namespace vanetza
