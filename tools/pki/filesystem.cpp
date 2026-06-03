#include "filesystem.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <fstream>
#include <stdexcept>
#include <system_error>

namespace vanetza
{
namespace pki
{

namespace
{

void write_file(const std::filesystem::path& path, const ByteBuffer& buffer)
{
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        throw std::runtime_error("could not open " + path.string() + " for writing");
    }
    ofs.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    ofs.flush();
    if (!ofs) {
        throw std::runtime_error("could not write " + path.string());
    }
}

} // namespace

void write(const std::filesystem::path& path, const ByteBuffer& buffer)
{
    // Write to temporary file first and atomically rename it later
    std::filesystem::path tmp = path;
    tmp += ".tmp";

    try {
        write_file(tmp, buffer);
        std::filesystem::rename(tmp, path);
    } catch (...) {
        // clean up temporary file
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        throw;
    }
}

ByteBuffer read(const std::filesystem::path& path)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        throw std::runtime_error("could not open " + path.string() + " for reading");
    }

    ByteBuffer buffer { std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>() };
    if (ifs.bad()) {
        throw std::runtime_error("I/O error while reading " + path.string());
    }
    return buffer;
}

} // namespace pki
} // namespace vanetza
