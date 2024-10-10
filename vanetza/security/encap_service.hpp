#ifndef FD3D1A69_8B8D_4DC1_8975_9FEB7A791B56
#define FD3D1A69_8B8D_4DC1_8975_9FEB7A791B56

#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/sign_service.hpp>
#include <boost/variant/variant.hpp>

namespace vanetza
{
namespace security
{

/**
 * Input data for encapsulating a packet in a secured message.
 * 
 * According to TS 102 723-8 V1.1.1, SN-ENCAP.request offers the very same
 * functionality as SN-SIGN.request and SN-ENCRYPT.request.
 * 
 * Since encryption is not yet implemented, so only SignRequest is included.
 */
using EncapRequest = boost::variant<SignRequest>;

/**
 * Confirmation of the encapsulation process (SN-ENCAP.confirm).
 * 
 * TS 102 723-8 V1.1.1 includes only sec_packet but cannot report any errors.
 * Instead of throwing exceptions, the variant may convey an error code instead
 * of a SecuredMessage.
 */
struct EncapConfirm : public boost::variant<SecuredMessage, SignConfirmError>
{
public:
    static EncapConfirm from(SignConfirm&&);

private:
    using variant::variant;
};

/**
 * Dispatch an encapsulation request to the responsible service.
 * 
 * \param encap_request SN-ENCAP.request data
 * \param sign_service service handling signing requests
 * \return SN-ENCAP.confirm
 */
EncapConfirm dispatch(EncapRequest&& encap_request, SignService* sign_service);

} // namespace security
} // namespace vanetza

#endif /* FD3D1A69_8B8D_4DC1_8975_9FEB7A791B56 */
