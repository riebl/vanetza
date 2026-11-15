#include <vanetza/security/psa_error.hpp>
#include <cstdio>
#include <string>

namespace vanetza
{
namespace security
{
namespace
{

// PSA Crypto API reserves this range for its status codes, Mbed TLS error codes lie outside
constexpr int psa_status_min = -255;
constexpr int psa_status_max = -128;

// native codes of the PSA implementation with the meaning of the failed operation, i.e. one category per condition
class PsaCategory : public std::error_category
{
public:
    explicit PsaCategory(SecurityModuleError condition) : m_condition(condition) {}

    const char* name() const noexcept override
    {
        switch (m_condition) {
            case SecurityModuleError::InvalidKeyReference:
                return "psa.invalid_key_reference";
            case SecurityModuleError::UnsupportedKeyType:
                return "psa.unsupported_key_type";
            case SecurityModuleError::ModuleFailure:
                return "psa.module_failure";
            case SecurityModuleError::KeyNotFound:
                return "psa.key_not_found";
            case SecurityModuleError::InvalidPublicKey:
                return "psa.invalid_public_key";
            case SecurityModuleError::DecryptionFailure:
                return "psa.decryption_failure";
            case SecurityModuleError::InvalidPrivateKey:
                return "psa.invalid_private_key";
            default:
                return "psa";
        }
    }

    std::string message(int value) const override
    {
        char buffer[32];
        if (value >= psa_status_min && value <= psa_status_max) {
            std::snprintf(buffer, sizeof(buffer), "PSA status %d", value);
        } else {
            std::snprintf(buffer, sizeof(buffer), "Mbed TLS error -0x%04X", static_cast<unsigned>(-value));
        }
        return buffer;
    }

    std::error_condition default_error_condition(int) const noexcept override
    {
        return make_error_condition(m_condition);
    }

private:
    SecurityModuleError m_condition;
};

template<SecurityModuleError Condition> const std::error_category& psa_category() noexcept
{
    static const PsaCategory category { Condition };
    return category;
}

const std::error_category& psa_category(SecurityModuleError condition) noexcept
{
    switch (condition) {
        case SecurityModuleError::InvalidKeyReference:
            return psa_category<SecurityModuleError::InvalidKeyReference>();
        case SecurityModuleError::UnsupportedKeyType:
            return psa_category<SecurityModuleError::UnsupportedKeyType>();
        case SecurityModuleError::ModuleFailure:
            return psa_category<SecurityModuleError::ModuleFailure>();
        case SecurityModuleError::KeyNotFound:
            return psa_category<SecurityModuleError::KeyNotFound>();
        case SecurityModuleError::InvalidPublicKey:
            return psa_category<SecurityModuleError::InvalidPublicKey>();
        case SecurityModuleError::DecryptionFailure:
            return psa_category<SecurityModuleError::DecryptionFailure>();
        case SecurityModuleError::InvalidPrivateKey:
            return psa_category<SecurityModuleError::InvalidPrivateKey>();
        default:
            return psa_category<SecurityModuleError::ModuleFailure>();
    }
}

} // namespace

std::error_code make_psa_error(int code, SecurityModuleError condition) noexcept
{
    return std::error_code(code, psa_category(condition));
}

} // namespace security
} // namespace vanetza
