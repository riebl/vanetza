#ifndef CERTIFICATE_MODIFICATIONS_HPP
#define CERTIFICATE_MODIFICATIONS_HPP

#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/certificate.hpp>

namespace vanetza
{
namespace security
{

void certificate_remove_attribute(Certificate&, const SubjectAttributeType&);

void certificate_remove_restriction(Certificate&, const ValidityRestrictionType&);

void certificate_add_permission(Certificate&, const ItsAid aid);

void certificate_add_permission(Certificate&, const ItsAid aid, const ByteBuffer ssp);

} // namespace security
} // namespace vanetza

#endif // CERTIFICATE_MODIFICATIONS_HPP
