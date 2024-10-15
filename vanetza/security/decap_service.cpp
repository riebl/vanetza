#include <vanetza/security/decap_service.hpp>
#include <boost/variant/static_visitor.hpp>

namespace vanetza
{
namespace security
{

bool is_successful(const DecapReport& report)
{
    return report == VerificationReport::Success;
}

bool operator==(const DecapReport& decap, VerificationReport verification)
{
    struct Visitor : public boost::static_visitor<bool>
    {
        Visitor(VerificationReport report) : expected(report) {}

        bool operator()(VerificationReport report) const
        {
            return report == expected;
        }

        bool operator()(boost::blank) const
        {
            return false;
        }

        VerificationReport expected;
    };

    return boost::apply_visitor(Visitor(verification), decap);
}

bool operator==(VerificationReport verification, const DecapReport& decap)
{
    return (decap == verification);
}

DecapConfirm DecapConfirm::from(VerifyConfirm&& verify, const SecuredMessageView& msg_view)
{
    DecapConfirm decap;
    decap.plaintext_payload = get_payload_copy(msg_view);
    decap.report = verify.report;
    decap.certificate_validity = verify.certificate_validity;
    decap.its_aid = verify.its_aid;
    decap.permissions = verify.permissions;
    return decap;
}

} // namespace security
} // namespace vanetza
