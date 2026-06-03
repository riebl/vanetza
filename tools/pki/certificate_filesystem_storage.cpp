#include "certificate_filesystem_storage.hpp"
#include "filesystem.hpp"
#include "security_module.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/iterator_range.hpp>

namespace vanetza
{
namespace pki
{

CertificateFilesystemStorage::CertificateFilesystemStorage(std::shared_ptr<SecurityModule> sec,
    const std::filesystem::path& root, std::string extension) :
    m_security(sec), m_root(root), m_extension(std::move(extension))
{
    std::filesystem::create_directories(m_root);
}

boost::optional<Certificate> CertificateFilesystemStorage::fetch(const HashedId8& id) const
{
    const std::filesystem::path path = filename(id);
    if (std::filesystem::is_regular_file(path)) {
        ByteBuffer buffer = read(path);
        Certificate cert;
        if (cert.decode(buffer)) {
            return cert;
        }
    }

    return boost::none;
}

void CertificateFilesystemStorage::store(const Certificate& cert)
{
    HashedId8 id = cert.calculate_hashed_id8(*m_security);
    write(filename(id), cert.encode());
}

bool CertificateFilesystemStorage::erase(const HashedId8& id)
{
    return std::filesystem::remove(filename(id));
}

std::filesystem::path CertificateFilesystemStorage::filename(const HashedId8& id) const
{
    std::string filename = hexstring(id) + m_extension;
    std::filesystem::path path = m_root / filename;
    return path;
}

HashedId8Range CertificateFilesystemStorage::list() const
{
    auto rng =
        boost::make_iterator_range(std::filesystem::directory_iterator(m_root), std::filesystem::directory_iterator()) |
        boost::adaptors::filtered([this](const std::filesystem::directory_entry& e) {
            return e.path().extension() == m_extension && std::filesystem::is_regular_file(e.path()) &&
                   HashedId8::from_hexstring(e.path().stem().string()).has_value();
        }) |
        boost::adaptors::transformed([](const std::filesystem::directory_entry& e) {
            return *HashedId8::from_hexstring(e.path().stem().string());
        });
    return HashedId8Range(rng);
}

} // namespace pki
} // namespace vanetza
