#include <vanetza/common/serialization.hpp>
#include <vanetza/security/v3/persistence.hpp>
#include <fstream>
#include <iterator>

namespace vanetza
{
namespace security
{
namespace v3
{

Certificate load_certificate_from_file(const std::string& certificate_path)
{
    Certificate certificate;

    std::ifstream certificate_src;
    certificate_src.open(certificate_path, std::ios::in | std::ios::binary);
    vanetza::ByteBuffer buffer(std::istreambuf_iterator<char>(certificate_src), {});
    certificate.decode(buffer);

    return certificate;
}

void save_certificate_to_file(const std::string& certificate_path, const Certificate& certificate)
{
    std::ofstream dest;
    dest.open(certificate_path.c_str(), std::ios::out | std::ios::binary);

    OutputArchive archive(dest);
    serialize(archive, certificate);
}

} // namespace v3
} // namespace security
} // namespace vanetza
