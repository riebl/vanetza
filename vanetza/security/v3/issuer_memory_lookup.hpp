#pragma once
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/issuer_lookup.hpp>
#include <unordered_map>

namespace vanetza
{
namespace security
{
namespace v3
{

/**
 * In-memory IssuerLookup populated programmatically with CA certificates.
 */
class IssuerMemoryLookup : public IssuerLookup
{
public:
    /**
     * Insert or replace a CA certificate, keyed by its own HashedId8 digest.
     * \param cert CA certificate
     * \return true if stored, false if rejected (not a CA cert or digest unavailable)
     */
    bool insert(const Certificate& cert);

    const Certificate* find_issuer(const HashedId8& digest) const override;

private:
    std::unordered_map<HashedId8, Certificate> m_certificates;
};

} // namespace v3
} // namespace security
} // namespace vanetza
