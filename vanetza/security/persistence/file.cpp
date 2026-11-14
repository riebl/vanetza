#include <vanetza/security/persistence/file.hpp>
#include <cerrno>
#include <fstream>
#include <iterator>

namespace vanetza
{
namespace security
{
namespace persistence
{

namespace
{

// file streams do not report why opening failed, errno is set by the underlying system call
std::error_code stream_open_error()
{
    return errno != 0 ? std::error_code(errno, std::generic_category()) : std::make_error_code(std::errc::io_error);
}

} // namespace

expected<ByteBuffer> read_file(const std::filesystem::path& path)
{
    errno = 0;
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return stream_open_error();
    }
    ByteBuffer content { std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>() };
    if (file.bad()) {
        return std::make_error_code(std::errc::io_error);
    }
    return content;
}

std::error_code write_file(const std::filesystem::path& path, const ByteBuffer& content)
{
    errno = 0;
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        return stream_open_error();
    }
    file.write(reinterpret_cast<const char*>(content.data()), content.size());
    file.close();
    if (!file) {
        return std::make_error_code(std::errc::io_error);
    }
    return std::error_code();
}

std::error_code write_owner_only_file(const std::filesystem::path& path, const ByteBuffer& content)
{
    // empty file first, its content follows only after it has been restricted
    std::error_code error = write_file(path, ByteBuffer {});
    if (error) {
        return error;
    }
    const auto owner_only = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
    std::filesystem::permissions(path, owner_only, std::filesystem::perm_options::replace, error);
    if (error) {
        return error;
    }
    return write_file(path, content);
}

} // namespace persistence
} // namespace security
} // namespace vanetza
