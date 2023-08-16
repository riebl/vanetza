#ifndef CHECK_ENCRYPTION_PARAMETER_HPP_5UDSKSNK
#define CHECK_ENCRYPTION_PARAMETER_HPP_5UDSKSNK

#include <vanetza/security/v2/encryption_parameter.hpp>
#include <vanetza/security/tests/check_basic_elements.hpp>

namespace vanetza
{
namespace security
{
namespace v2
{

/**
 * \brief check if the two EncryptionParameter are equal
 * \param expected the expected value
 * \param actual the actual value
 */
void check(const EncryptionParameter& expected, const EncryptionParameter& actual);

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* CHECK_ENCRYPTION_PARAMETER_HPP_5UDSKSNK */
