#pragma once
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/v3/certificate_provider.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>
#include <vanetza/security/v3/secured_message.hpp>

namespace vanetza
{
namespace security
{

// forward declarations
class Backend;

namespace v3
{

/**
 * SignService immediately signing the message using given
 */
class StraightSignService : public SignService
{
public:
   StraightSignService(CertificateProvider&, Backend&, SignHeaderPolicy&);
   SignConfirm sign(SignRequest&&) override;

private:
    CertificateProvider & m_certificates;
    Backend& m_backend;
    SignHeaderPolicy& m_policy;
};
    

/**
 * SignService without real cryptography but dummy signature
 */
class DummySignService : public SignService
{
public:
    /**
     * \param rt runtime for appropriate generation time
     */ 
    DummySignService(const Runtime& rt);
    SignConfirm sign(SignRequest&&) override;

private:
    const Runtime& m_runtime;
};

/**
 * Calculate message hash (combination of hashes).
 * 
 * This function creates the message hash according to IEEE 1609.2 cause 5.3.1.2.2
 * for verification type "certificate", i.e. not "self-signed" messages.
 * 
 * \param backend backend for cryptographic operations
 * \param algo hash algorithm
 * \param data message payload (data to be signed)
 * \param signing certificate used for signing
 * \return message digest
 */
ByteBuffer calculate_message_hash(Backend&, HashAlgorithm, const ByteBuffer& data, const Certificate& signing);

/**
 * Determine the hash algorithm for a given key type.
 * \see IEEE 1609.2 clause 5.3.1.2.2 rule a)
 * \param key_type key type
 * \return suitable hash algorithm
 */
HashAlgorithm specified_hash_algorithm(KeyType key_type);

} // namespace v3
} // namespace security
} // namespace vanetza
