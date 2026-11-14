#include <vanetza/security/persistence/file.hpp>
#include <vanetza/security/persistence/key_reference.hpp>
#include <utility>

namespace vanetza
{
namespace security
{
namespace persistence
{

expected<KeyReference> load_key_reference(const std::filesystem::path& path)
{
    expected<ByteBuffer> content = read_file(path);
    if (!content) {
        return content.error();
    } else if (content->empty()) {
        return std::make_error_code(std::errc::illegal_byte_sequence);
    }
    return KeyReference { std::move(*content) };
}

std::error_code save_key_reference(const std::filesystem::path& path, const KeyReference& reference)
{
    if (reference.data.empty()) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    return write_owner_only_file(path, reference.data);
}

} // namespace persistence
} // namespace security
} // namespace vanetza
