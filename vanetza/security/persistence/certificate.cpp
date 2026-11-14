#include <vanetza/asn1/asn1c_error.hpp>
#include <vanetza/security/persistence/certificate.hpp>
#include <vanetza/security/persistence/file.hpp>

namespace vanetza
{
namespace security
{
namespace persistence
{

expected<v3::Certificate> load_v3_certificate(const std::filesystem::path& path)
{
    const expected<ByteBuffer> content = read_file(path);
    if (!content) {
        return content.error();
    }
    v3::Certificate certificate;
    asn1::asn1c_error error;
    certificate.decode(*content, error);
    if (error) {
        return std::make_error_code(std::errc::illegal_byte_sequence);
    }
    return certificate;
}

std::error_code save_certificate(const std::filesystem::path& path, const v3::Certificate& certificate)
{
    asn1::asn1c_error error;
    const ByteBuffer encoded = certificate.encode(error);
    if (error) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    return write_file(path, encoded);
}

} // namespace persistence
} // namespace security
} // namespace vanetza
