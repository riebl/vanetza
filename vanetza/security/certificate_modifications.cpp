#include <vanetza/security/certificate_modifications.hpp>
#include <boost/variant/get.hpp>

namespace vanetza
{
namespace security
{

void certificate_remove_attribute(Certificate& cert, const SubjectAttributeType& type)
{
    for (auto it = cert.subject_attributes.begin(); it != cert.subject_attributes.end(); ++it) {
        if (get_type(*it) == type) {
            it = cert.subject_attributes.erase(it);
        }
    }
}

void certificate_remove_restriction(Certificate& cert, const ValidityRestrictionType& type)
{
    for (auto it = cert.validity_restriction.begin(); it != cert.validity_restriction.end(); ++it) {
        if (get_type(*it) == type) {
            it = cert.validity_restriction.erase(it);
        }
    }
}

void certificate_add_permission(Certificate& cert, const ItsAid aid)
{
    for (auto& item : cert.subject_attributes) {
        if (get_type(item) == SubjectAttributeType::Its_Aid_List) {
            auto& list = boost::get<std::list<IntX> >(item);
            list.push_back(IntX(aid));

            return;
        }
    }

    cert.subject_attributes.push_back(std::list<IntX>({ IntX(aid) }));
}

void certificate_add_permission(Certificate& cert, const ItsAid aid, const ByteBuffer ssp)
{
    ItsAidSsp permission({ IntX(aid), ssp });

    for (auto& item : cert.subject_attributes) {
        if (get_type(item) == SubjectAttributeType::Its_Aid_Ssp_List) {
            auto& list = boost::get<std::list<ItsAidSsp> >(item);
            list.push_back(permission);

            return;
        }
    }

    cert.subject_attributes.push_back(std::list<ItsAidSsp>({ permission }));
}

} // namespace security
} // namespace vanetza
