#include "crl_store.hpp"
#include "certificate_revocation_list.hpp"
#include "filesystem.hpp"
#include "hexstring.hpp"
#include "security_module.hpp"

namespace vanetza
{
namespace pki
{

CrlFilesystemStore::CrlFilesystemStore(std::shared_ptr<SecurityModule> security, const std::filesystem::path& root) :
    m_security(security), m_root(root)
{
    std::filesystem::create_directories(m_root);
    for (const auto& entry : std::filesystem::directory_iterator(m_root)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".crl") {
            continue;
        }
        ByteBuffer buf = read(entry.path());
        CertificateRevocationList crl;
        if (crl.decode(buf)) {
            index(crl);
        }
    }
}

bool CrlFilesystemStore::store(const CertificateRevocationList& crl)
{
    auto issuer = index(crl);
    if (!issuer) {
        return false;
    }
    write(filename(*issuer), crl.encode());
    return true;
}

bool CrlFilesystemStore::is_revoked(const security::HashedId8& issuer, const security::HashedId8& cert) const
{
    auto it = m_revoked.find(issuer);
    if (it == m_revoked.end()) {
        return false;
    }
    return it->second.count(cert) != 0;
}

std::filesystem::path CrlFilesystemStore::filename(const HashedId8& id) const
{
    return m_root / (hexstring(id.octets) + ".crl");
}

boost::optional<HashedId8> CrlFilesystemStore::index(const CertificateRevocationList& crl)
{
    auto issuer = crl.get_hashed_id8(*m_security);
    if (!issuer) {
        return boost::none;
    }
    auto entries = crl.revoked_entries();
    if (!entries) {
        return boost::none;
    }

    // Empty CRL is valid: it withdraws any prior revocations from this issuer.
    // Erase the existing bucket and only create a new one if there's content.
    m_revoked.erase(issuer->octets);
    if (!entries->empty()) {
        auto& bucket = m_revoked[issuer->octets];
        for (const auto& cert : *entries) {
            bucket.insert(cert.octets);
        }
    }
    return issuer;
}

} // namespace pki
} // namespace vanetza
