#include <vanetza/security/credential_storage.hpp>

namespace vanetza
{
namespace security
{

std::error_code CredentialStorage::visit(CredentialVisitor&) const
{
    return std::make_error_code(std::errc::operation_not_supported);
}

expected<bool> CredentialStorage::discard(const std::string&)
{
    return std::make_error_code(std::errc::operation_not_supported);
}

expected<bool> CredentialStorage::contains(const std::string&) const
{
    return std::make_error_code(std::errc::operation_not_supported);
}

} // namespace security
} // namespace vanetza
