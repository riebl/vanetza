#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <filesystem>

namespace vanetza
{
namespace pki
{

void write(const std::filesystem::path& path, const ByteBuffer&);
ByteBuffer read(const std::filesystem::path&);

} // namespace pki
} // namespace vanetza
