#include "trust_list_filesystem_storage.hpp"
#include "certificate_trust_list.hpp"
#include "filesystem.hpp"
#include "security_module.hpp"

namespace vanetza
{
namespace pki
{

TrustListFilesystemStorage::TrustListFilesystemStorage(std::shared_ptr<SecurityModule> security,
    const std::filesystem::path& root) : m_security(security), m_root(root)
{
    std::filesystem::create_directories(m_root);
}

void TrustListFilesystemStorage::store(const CertificateTrustList& ctl)
{
    boost::optional<HashedId8> id = ctl.get_hashed_id8(*m_security);
    if (id) {
        write(filename(*id), ctl.encode());
    } else {
        throw std::runtime_error("no HashedId8 known for given CTL");
    }
}

boost::optional<CertificateTrustList> TrustListFilesystemStorage::fetch(const HashedId8& id) const
{
    const std::filesystem::path path = filename(id);
    if (std::filesystem::is_regular_file(path)) {
        ByteBuffer buffer = read(path);
        CertificateTrustList ctl;
        if (ctl.decode(buffer)) {
            return ctl;
        }
    }

    return boost::none;
}

std::filesystem::path TrustListFilesystemStorage::filename(const HashedId8& id) const
{
    std::string filename = hexstring(id) + ".ctl";
    std::filesystem::path path = m_root / filename;
    return path;
}

} // namespace pki
} // namespace vanetza
