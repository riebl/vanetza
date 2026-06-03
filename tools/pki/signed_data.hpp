#pragma once

#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs103097Data-Signed.h>
#include <vanetza/asn1/security/Ieee1609Dot2Data.h>

namespace vanetza
{
namespace pki
{

class SignedData : public asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs103097Data_Signed_55P0_t>
{
public:
    using wrapper = asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs103097Data_Signed_55P0_t>;

    SignedData() : wrapper(asn_DEF_Vanetza_Security_EtsiTs103097Data_Signed_55P0)
    {
    }

    /**
     * Graft the envelope into a parent that takes over ownership.
     * Consuming: only callable on an rvalue, leaving the source empty.
     *
     * \param dest Ieee1609Dot2Data field of the parent to move the envelope into
     */
    void move_into(Vanetza_Security_Ieee1609Dot2Data_t& dest) &&;
};

} // namespace pki
} // namespace vanetza
