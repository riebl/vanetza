#ifndef F815BB22_3075_4A9D_9385_07876D800765
#define F815BB22_3075_4A9D_9385_07876D800765

#include <vanetza/common/its_aid.hpp>
#include <vanetza/net/packet_variant.hpp>
#include <vanetza/security/certificate_validity.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/verify_service.hpp>
#include <boost/optional/optional.hpp>
#include <boost/variant/variant.hpp>

namespace vanetza
{
namespace security
{

/**
 * \brief Input data for decapsulating a secured message.
 * 
 * The structure is equivalent to VerifyRequest, however, decapsulation may
 * also deal with decryption in future versions.
 * 
 * \see TS 102 723-8 v1.1.1 SN-DECAP.request
 */
struct DecapRequest
{
    DecapRequest(SecuredMessageView sec_msg_view) : sec_packet(sec_msg_view) {}
    SecuredMessageView sec_packet;
};

/**
 * \brief SN-DECAP.confirm report codes
 * \see TS 102 723-8 v1.1.1 table 27 (report field)
 * 
 * Instead of duplicating VerificationReport values and the linked burden keeping
 * these values consistent, DecapReport is a variant incorporating VerificationReport.
 * When decryption is implemented, a DecryptionReport may be added to the variant.
 * 
 * The boost::blank entry indicates that the SecuredMessage was neither signed nor encrypted.
 */
using DecapReport = boost::variant<boost::blank, VerificationReport>;

/**
 * \brief Check if report indicates a successful decapsulation.
 *
 * Either verification or decryption needs to be successful.
 * An unsecured message cannot lead to a succesful decapsulation result.
 * 
 * \param report to check
 * \return true if either verification or decryption was successful
 */
bool is_successful(const DecapReport& report);

/**
 * \brief Check if decapsulation report matches a particular verification report.
 * 
 * \param decap decapsulation report
 * \param verification verification report
 * \return true if decapsulation matches verification
 */
bool operator==(const DecapReport& decap, VerificationReport verification);
bool operator==(VerificationReport verification, const DecapReport& decap);

/**
 * \brief SN-DECAP.confirm
 * \see TS 102 723-8 v1.1.1 table 27
 */
struct DecapConfirm
{
    PacketVariant plaintext_payload; // mandatory (plaintext_packet_length also covered by data type)
    DecapReport report; // mandatory
    CertificateValidity certificate_validity; // non-standard extension
    boost::optional<HashedId8> certificate_id; // optional
    ItsAid its_aid; // mandatory (its_ait_lenth also covered by data type)
    ByteBuffer permissions; // mandatory
};

} // namespace security
} // namespace vanetza

#endif /* F815BB22_3075_4A9D_9385_07876D800765 */
