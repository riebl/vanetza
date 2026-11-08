#pragma once
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/key_reference.hpp>
#include <vanetza/security/v2/certificate.hpp>

namespace vanetza
{
namespace security
{
namespace v2
{

/**
 * \brief Own certificate along with its issuer and its private key held by a SecurityModule
 */
struct Credential
{
    Certificate certificate;
    Certificate issuer; // authorization authority (AA) which has issued certificate
    KeyReference key;
};

/**
 * \brief Source of credentials for signing, e.g. the station's authorization tickets
 */
class CredentialProvider
{
public:
    /**
     * Get credential for signing a message
     * \param aid ITS-AID of the message
     * \return credential for signing messages of aid or nullptr if none is available
     */
    virtual const Credential* signing_credential(ItsAid aid) = 0;

    virtual ~CredentialProvider() = default;
};

} // namespace v2
} // namespace security
} // namespace vanetza
