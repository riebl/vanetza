#include <vanetza/asn1/asn1c_error.hpp>
#include <vanetza/common/serialization_buffer.hpp>
#include <vanetza/security/exception.hpp>
#include <vanetza/security/persistence/certificate.hpp>
#include <vanetza/security/persistence/file.hpp>
#include <boost/iostreams/stream_buffer.hpp>
#include <stdexcept>

namespace vanetza
{
namespace security
{
namespace persistence
{

expected<v2::Certificate> load_v2_certificate(const std::filesystem::path& path)
{
    const expected<ByteBuffer> content = read_file(path);
    if (!content) {
        return content.error();
    }
    v2::Certificate certificate;
    byte_buffer_source source(*content);
    boost::iostreams::stream_buffer<byte_buffer_source> stream(source);
    InputArchive archive(stream);
    try {
        v2::deserialize(archive, certificate);
    } catch (const std::runtime_error&) {
        // InputArchive::Exception, deserialization_error and std::overflow_error of v2 deserialization
        return std::make_error_code(std::errc::illegal_byte_sequence);
    }
    if (!archive.is_good()) {
        return std::make_error_code(std::errc::illegal_byte_sequence);
    }
    return certificate;
}

std::error_code save_certificate(const std::filesystem::path& path, const v2::Certificate& certificate)
{
    ByteBuffer serialized;
    try {
        serialize_into_buffer(certificate, serialized);
    } catch (const serialization_error&) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    return write_file(path, serialized);
}

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
