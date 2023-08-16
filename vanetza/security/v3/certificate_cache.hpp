#pragma once
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <unordered_map>

namespace vanetza
{
namespace security
{
namespace v3
{

/**
 * CertificateCache stores validated v1.3.1 certificates for later lookup.
 * Required for checking messages' signatures containing only a certificate digest.
 */
class CertificateCache
{
public:
    /**
     * Lookup certificate based on given digest
     * \param digest certificate digest
     * \return certificate matching digest
     */
    const Certificate* lookup(const HashedId8& digest) const;

    /**
     * Store a (pre-validated) certificate in cache
     * \param cert certificate
     */
    void store(const Certificate& cert);

    size_t size() const { return m_storage.size(); }

private:
    // TODO add bounded capacity and automatic removal of expired certificates
    std::unordered_map<HashedId8, Certificate> m_storage;
};

} // namespace v3
} // namespace security
} // namespace vanetza
