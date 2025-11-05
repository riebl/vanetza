#ifndef SIGN_SERVICE_HPP_4MDQBSEF
#define SIGN_SERVICE_HPP_4MDQBSEF

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/net/packet.hpp>
#include <vanetza/security/hash_algorithm.hpp>
#include <vanetza/security/key_type.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/signing_policy.hpp>
#include <boost/optional/optional.hpp>
#include <functional>

namespace vanetza
{

// forward declaration
class Runtime;

namespace security
{

// mandatory SN-SIGN.request parameters
struct SignRequest
{
    DownPacket plain_message;
    ItsAid its_aid;
    ByteBuffer permissions;
    bool external_payload = false;
    bool self_signed = false;
};

enum class SignConfirmError
{
    Unspecified,
    No_Certificate,
    No_Service,
};

// mandatory SN-SIGN.confirm parameters
struct SignConfirm
{
    SignConfirm(SignConfirmError error, boost::optional<SecuredMessage> message)
        : error(error), secured_message(std::move(message))
    {
    }

    static SignConfirm success(SecuredMessage&& message)
    {
        return { SignConfirmError::Unspecified, std::move(message) };
    }

    static SignConfirm failure(SignConfirmError error)
    {
        return { error, boost::none };
    }

    SignConfirmError error;
    boost::optional<SecuredMessage> secured_message;
};

/**
 * Equivalant of SN-SIGN service in TS 102 723-8 v1.1.1
 */
class SignService
{
public:
    virtual ~SignService() = default;
    virtual SignConfirm sign(SignRequest&&) = 0;
};

} // namespace security
} // namespace vanetza

#endif /* SIGN_SERVICE_HPP_4MDQBSEF */
