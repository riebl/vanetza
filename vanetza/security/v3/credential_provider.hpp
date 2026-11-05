#pragma once
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/key_reference.hpp>
#include <vanetza/security/v3/certificate.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

/**
 * \brief Own certificate along with its private key held by a SecurityModule
 */
struct Credential
{
    Certificate certificate;
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
     * \return credential permitted for aid or nullptr if none is available
     */
    virtual const Credential* signing_credential(ItsAid aid) = 0;

    virtual ~CredentialProvider() = default;
};

} // namespace v3
} // namespace security
} // namespace vanetza
