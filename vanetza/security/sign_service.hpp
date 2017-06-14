#ifndef SIGN_SERVICE_HPP_4MDQBSEF
#define SIGN_SERVICE_HPP_4MDQBSEF

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/net/packet.hpp>
#include <vanetza/security/its_aid.hpp>
#include <vanetza/security/secured_message.hpp>
#include <functional>

namespace vanetza
{

// forward declaration
class Runtime;

namespace security
{

// forward declarations
class Backend;
class CertificateManager;

// mandatory SN-SIGN.request parameters
struct SignRequest
{
    DownPacket plain_message;
    IntX its_aid;
    ByteBuffer permissions;
};

// mandatory SN-SIGN.confirm parameters
struct SignConfirm
{
    SecuredMessage secured_message;
};

/**
 * Equivalant of SN-SIGN service in TS 102 723-8 v1.1.1
 */
using SignService = std::function<SignConfirm(SignRequest&&)>;

/*
 * SignService immediately signing the message using given
 * \param rt runtime
 * \param cert certificate manager
 * \param backend cryptographic backend
 * \return callable sign service
 */
SignService straight_sign_service(Runtime&, CertificateManager&, Backend&);

/**
 * SignService deferring actually signature calculation using EcdsaSignatureFuture
 * \param rt runtime
 * \param cert certificate manager
 * \param backend cryptographic backend
 * \return callable sign service
 */
SignService deferred_sign_service(Runtime&, CertificateManager&, Backend&);

} // namespace security
} // namespace vanetza

#endif /* SIGN_SERVICE_HPP_4MDQBSEF */

